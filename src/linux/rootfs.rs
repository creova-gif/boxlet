//! Linux root filesystem isolation via `MS_PRIVATE`, bind-mount, `pivot_root`, `/proc`, and masked paths.

use std::fs;
use std::path::{Path, PathBuf};

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::{chdir, pivot_root};
use oci_spec::runtime::Spec;

use crate::error::{BoxletError, Result};
use crate::traits::RootfsProvider;

/// V1 root filesystem provider using direct bind-mount + `pivot_root`.
///
/// V2 can replace this internal strategy with overlayfs snapshotting and diffing
/// without changing `Engine` or `RuntimeBackend`.
#[derive(Debug, Default, Clone)]
pub(crate) struct BindPivotRootfs;

impl RootfsProvider for BindPivotRootfs {
    fn prepare(&self, _container_id: &str, rootfs_path: &Path) -> Result<PathBuf> {
        if !rootfs_path.is_dir() {
            return Err(BoxletError::Runtime {
                subsystem: "rootfs",
                message: format!(
                    "bundle rootfs '{}' does not exist or is not a directory",
                    rootfs_path.display()
                ),
            });
        }
        Ok(rootfs_path.to_path_buf())
    }

    fn cleanup(&self, _container_id: &str, _prepared_path: &Path) -> Result<()> {
        // BindPivotRootfs mounts exclusively inside the container's private mount namespace,
        // so the kernel tears down all mounts automatically when the last process exits.
        Ok(())
    }
}

/// Switches the current process's root filesystem to `new_root` using `pivot_root(2)`.
pub(crate) fn setup_and_pivot_root(new_root: &Path, spec: &Spec) -> Result<()> {
    // 1. Prevent mount events from propagating back to the host mount namespace.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("mount(/, MS_PRIVATE) failed: {err}"),
    })?;

    // 2. Bind-mount new_root onto itself so it is a mount point (required by pivot_root).
    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("bind mount rootfs '{}' failed: {err}", new_root.display()),
    })?;

    // 3. Mount /proc inside the new rootfs.
    let proc_dir = new_root.join("proc");
    fs::create_dir_all(&proc_dir).map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("failed to create '{}': {err}", proc_dir.display()),
    })?;
    mount(
        Some("proc"),
        &proc_dir,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("mount(/proc) failed: {err}"),
    })?;

    // 4. Mount minimal /dev tmpfs and bind essential character device nodes.
    setup_minimal_dev(new_root)?;

    // 5. Pivot root and detach old host root.
    let put_old = new_root.join(".boxlet_old_root");
    fs::create_dir_all(&put_old).map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("failed to create put_old '{}': {err}", put_old.display()),
    })?;

    pivot_root(new_root, &put_old).map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("pivot_root('{}') failed: {err}", new_root.display()),
    })?;

    chdir("/").map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("chdir('/') after pivot_root failed: {err}"),
    })?;

    umount2("/.boxlet_old_root", MntFlags::MNT_DETACH).map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("umount2(old_root) failed: {err}"),
    })?;

    let _ = fs::remove_dir("/.boxlet_old_root");

    // 6. Apply OCI maskedPaths and readonlyPaths inside the pivoted root.
    apply_path_protections(spec)?;

    // 7. Remount rootfs read-only if requested by OCI spec.
    if spec
        .root()
        .as_ref()
        .and_then(|r| r.readonly())
        .unwrap_or(false)
    {
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|err| BoxletError::Runtime {
            subsystem: "rootfs",
            message: format!("remount('/', MS_RDONLY) failed: {err}"),
        })?;
    }

    Ok(())
}

fn setup_minimal_dev(new_root: &Path) -> Result<()> {
    let dev_dir = new_root.join("dev");
    fs::create_dir_all(&dev_dir).map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("failed to create '{}': {err}", dev_dir.display()),
    })?;

    mount(
        Some("tmpfs"),
        &dev_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        Some("mode=755,size=65536k"),
    )
    .map_err(|err| BoxletError::Runtime {
        subsystem: "rootfs",
        message: format!("mount(/dev tmpfs) failed: {err}"),
    })?;

    for dev_name in ["null", "zero", "full", "random", "urandom", "tty"] {
        let host_dev = Path::new("/dev").join(dev_name);
        if !host_dev.exists() {
            continue;
        }
        let target = dev_dir.join(dev_name);
        let _ = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&target);
        mount(
            Some(&host_dev),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|err| BoxletError::Runtime {
            subsystem: "rootfs",
            message: format!("bind mount /dev/{dev_name} failed: {err}"),
        })?;
    }

    Ok(())
}

fn apply_path_protections(spec: &Spec) -> Result<()> {
    let Some(linux) = spec.linux() else {
        return Ok(());
    };

    if let Some(masked) = linux.masked_paths() {
        for raw_path in masked {
            let p = Path::new(raw_path);
            if !p.exists() {
                continue;
            }
            if p.is_dir() {
                let _ = mount(
                    Some("tmpfs"),
                    p,
                    Some("tmpfs"),
                    MsFlags::MS_RDONLY,
                    Some("size=0"),
                );
            } else {
                let _ = mount(
                    Some("/dev/null"),
                    p,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                );
            }
        }
    }

    if let Some(readonly) = linux.readonly_paths() {
        for raw_path in readonly {
            let p = Path::new(raw_path);
            if !p.exists() {
                continue;
            }
            let _ = mount(
                Some(p),
                p,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            );
            let _ = mount(
                None::<&str>,
                p,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
                None::<&str>,
            );
        }
    }

    Ok(())
}
