//! OCI Runtime Specification bundle loading, scaffolding, and container lifecycle state store.

pub mod state;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use oci_spec::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, ProcessBuilder,
    RootBuilder, Spec, SpecBuilder, UserBuilder,
};

use crate::error::{BoxletError, Result};

/// Default OCI runtime specification version reported in `state.json`.
pub const OCI_RUNTIME_VERSION: &str = "1.0.2";

/// Standard BusyBox applet symlinks created in `<bundle>/rootfs/bin` when `--busybox` is provided.
const BUSYBOX_APPLETS: &[&str] = &[
    "sh", "echo", "sleep", "true", "false", "cat", "dd", "head", "grep", "mount", "chroot", "wc",
    "rm", "mkdir", "ls", "cp", "mv", "ln", "env", "id", "pwd", "uname",
];

/// Builder for scaffolding a valid, spec-compliant OCI bundle directory (`config.json` + `rootfs`).
#[derive(Debug, Clone)]
pub struct BundleBuilder {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    hostname: String,
    readonly_rootfs: bool,
    busybox_path: Option<PathBuf>,
    rootless_uid_gid: Option<(u32, u32)>,
}

impl Default for BundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BundleBuilder {
    /// Creates a new [`BundleBuilder`] initialized with Boxlet V1 defaults.
    pub fn new() -> Self {
        Self {
            args: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo boxlet-ok".to_string(),
            ],
            env: vec!["PATH=/bin:/usr/bin".to_string()],
            cwd: "/".to_string(),
            hostname: "boxlet-sandbox".to_string(),
            readonly_rootfs: false,
            busybox_path: None,
            rootless_uid_gid: None,
        }
    }

    /// Sets the container entrypoint and arguments (`process.args`).
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Configures `process.args` to execute `<cmd>` via `/bin/sh -c <cmd>`.
    pub fn with_shell_command(mut self, cmd: impl Into<String>) -> Self {
        self.args = vec!["/bin/sh".to_string(), "-c".to_string(), cmd.into()];
        self
    }

    /// Sets the container environment variable list (`process.env`).
    pub fn with_env(mut self, env: Vec<String>) -> Self {
        self.env = env;
        self
    }

    /// Sets the working directory inside the container (`process.cwd`).
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = cwd.into();
        self
    }

    /// Sets the container UTS hostname (`hostname` and `rootfs/etc/hostname`).
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }

    /// Sets whether the root filesystem is mounted read-only (`root.readonly`).
    pub fn with_readonly_rootfs(mut self, readonly: bool) -> Self {
        self.readonly_rootfs = readonly;
        self
    }

    /// Copies a static `busybox` binary into `rootfs/bin/busybox` and populates standard applet symlinks.
    pub fn with_busybox(mut self, busybox_path: impl Into<PathBuf>) -> Self {
        self.busybox_path = Some(busybox_path.into());
        self
    }

    /// Enables or disables rootless user namespace configuration (`CLONE_NEWUSER`)
    /// mapping container root (`0:0`) to the current host effective UID/GID.
    pub fn with_rootless(mut self, rootless: bool) -> Self {
        if rootless {
            self.rootless_uid_gid = Some(current_host_uid_gid());
        } else {
            self.rootless_uid_gid = None;
        }
        self
    }

    /// Configures rootless user namespace (`CLONE_NEWUSER`) with an explicit
    /// single-user `0 -> host_uid` and `0 -> host_gid` mapping.
    pub fn with_uid_gid_mapping(mut self, host_uid: u32, host_gid: u32) -> Self {
        self.rootless_uid_gid = Some((host_uid, host_gid));
        self
    }

    /// Scaffolds `<bundle_dir>/rootfs` and writes `<bundle_dir>/config.json`, returning the generated [`Spec`].
    pub fn build(&self, bundle_dir: &Path) -> Result<Spec> {
        if self.args.is_empty() {
            return Err(BoxletError::InvalidPolicy {
                reason: "bundle process.args must not be empty".to_string(),
            });
        }
        if self.cwd.trim().is_empty() || !self.cwd.starts_with('/') {
            return Err(BoxletError::InvalidPolicy {
                reason: "bundle process.cwd must be a non-empty absolute path starting with '/'"
                    .to_string(),
            });
        }

        let rootfs_dir = bundle_dir.join("rootfs");
        reject_if_symlink(&rootfs_dir)?;
        for subdir in ["bin", "proc", "dev", "tmp", "etc"] {
            let dir_path = rootfs_dir.join(subdir);
            reject_if_symlink(&dir_path)?;
            fs::create_dir_all(&dir_path).map_err(|source| BoxletError::StateStore {
                path: dir_path,
                source,
            })?;
        }

        let hostname_file = rootfs_dir.join("etc").join("hostname");
        if fs::symlink_metadata(&hostname_file).is_ok() {
            fs::remove_file(&hostname_file).map_err(|source| BoxletError::StateStore {
                path: hostname_file.clone(),
                source,
            })?;
        }
        fs::write(&hostname_file, format!("{}\n", self.hostname)).map_err(|source| {
            BoxletError::StateStore {
                path: hostname_file,
                source,
            }
        })?;

        if let Some(ref bb_src) = self.busybox_path {
            if !bb_src.is_file() {
                return Err(BoxletError::StateStore {
                    path: bb_src.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "busybox binary not found or not a regular file",
                    ),
                });
            }
            let bin_dir = rootfs_dir.join("bin");
            let bb_dst = bin_dir.join("busybox");
            let bb_tmp = bin_dir.join(".busybox.tmp");
            if fs::symlink_metadata(&bb_tmp).is_ok() {
                let _ = fs::remove_file(&bb_tmp);
            }
            fs::copy(bb_src, &bb_tmp).map_err(|source| BoxletError::StateStore {
                path: bb_dst.clone(),
                source,
            })?;
            #[cfg(unix)]
            {
                fs::set_permissions(&bb_tmp, fs::Permissions::from_mode(0o755)).map_err(
                    |source| {
                        let _ = fs::remove_file(&bb_tmp);
                        BoxletError::StateStore {
                            path: bb_dst.clone(),
                            source,
                        }
                    },
                )?;
            }
            fs::rename(&bb_tmp, &bb_dst).map_err(|source| {
                let _ = fs::remove_file(&bb_tmp);
                BoxletError::StateStore {
                    path: bb_dst,
                    source,
                }
            })?;

            for applet in BUSYBOX_APPLETS {
                let applet_path = bin_dir.join(applet);
                if fs::symlink_metadata(&applet_path).is_ok() {
                    fs::remove_file(&applet_path).map_err(|source| BoxletError::StateStore {
                        path: applet_path.clone(),
                        source,
                    })?;
                }
                create_applet_symlink(Path::new("/bin/busybox"), &applet_path)?;
            }
        }

        let config_path = bundle_dir.join("config.json");
        let root = RootBuilder::default()
            .path(PathBuf::from("rootfs"))
            .readonly(self.readonly_rootfs)
            .build()
            .map_err(|source| BoxletError::OciSpec {
                path: config_path.clone(),
                source,
            })?;

        let user = UserBuilder::default()
            .uid(0u32)
            .gid(0u32)
            .build()
            .map_err(|source| BoxletError::OciSpec {
                path: config_path.clone(),
                source,
            })?;

        let mut process = ProcessBuilder::default()
            .terminal(false)
            .user(user)
            .args(self.args.clone())
            .env(self.env.clone())
            .cwd(PathBuf::from(&self.cwd))
            .no_new_privileges(true)
            .build()
            .map_err(|source| BoxletError::OciSpec {
                path: config_path.clone(),
                source,
            })?;
        process.set_capabilities(None);
        process.set_rlimits(None);

        let namespace_types = [
            LinuxNamespaceType::Pid,
            LinuxNamespaceType::Mount,
            LinuxNamespaceType::Uts,
            LinuxNamespaceType::Ipc,
            LinuxNamespaceType::Network,
        ];
        let mut namespaces = Vec::with_capacity(namespace_types.len() + 1);
        for ns_type in namespace_types {
            let ns = LinuxNamespaceBuilder::default()
                .typ(ns_type)
                .build()
                .map_err(|source| BoxletError::OciSpec {
                    path: config_path.clone(),
                    source,
                })?;
            namespaces.push(ns);
        }
        if self.rootless_uid_gid.is_some() {
            let user_ns = LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::User)
                .build()
                .map_err(|source| BoxletError::OciSpec {
                    path: config_path.clone(),
                    source,
                })?;
            namespaces.push(user_ns);
        }

        let mut linux_builder = LinuxBuilder::default().namespaces(namespaces);
        if let Some((host_uid, host_gid)) = self.rootless_uid_gid {
            let uid_map = LinuxIdMappingBuilder::default()
                .container_id(0u32)
                .host_id(host_uid)
                .size(1u32)
                .build()
                .map_err(|source| BoxletError::OciSpec {
                    path: config_path.clone(),
                    source,
                })?;
            let gid_map = LinuxIdMappingBuilder::default()
                .container_id(0u32)
                .host_id(host_gid)
                .size(1u32)
                .build()
                .map_err(|source| BoxletError::OciSpec {
                    path: config_path.clone(),
                    source,
                })?;
            linux_builder = linux_builder
                .uid_mappings(vec![uid_map])
                .gid_mappings(vec![gid_map]);
        }

        let mut linux = linux_builder
            .build()
            .map_err(|source| BoxletError::OciSpec {
                path: config_path.clone(),
                source,
            })?;
        linux.set_masked_paths(None);
        linux.set_readonly_paths(None);

        let spec = SpecBuilder::default()
            .version(OCI_RUNTIME_VERSION)
            .root(root)
            .hostname(self.hostname.clone())
            .process(process)
            .linux(linux)
            .build()
            .map_err(|source| BoxletError::OciSpec {
                path: config_path.clone(),
                source,
            })?;

        spec.save(&config_path)
            .map_err(|source| BoxletError::OciSpec {
                path: config_path,
                source,
            })?;

        Ok(spec)
    }
}

#[cfg(target_os = "linux")]
fn current_host_uid_gid() -> (u32, u32) {
    (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    )
}

#[cfg(not(target_os = "linux"))]
fn current_host_uid_gid() -> (u32, u32) {
    (1000, 1000)
}

fn reject_if_symlink(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(BoxletError::StateStore {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "bundle directory component must not be a symlink",
                ),
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_applet_symlink(target: &Path, link_path: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link_path).map_err(|source| BoxletError::StateStore {
        path: link_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn create_applet_symlink(_target: &Path, link_path: &Path) -> Result<()> {
    Err(BoxletError::StateStore {
        path: link_path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "busybox applet symlinks require a Unix host filesystem",
        ),
    })
}

/// Loads and validates `<bundle>/config.json` via `oci-spec`.
pub fn load_bundle_spec(bundle: &Path) -> Result<Spec> {
    let config_path = bundle.join("config.json");
    Spec::load(&config_path).map_err(|source| BoxletError::OciSpec {
        path: config_path,
        source,
    })
}

/// Validates that a container ID is non-empty and safe for filesystem paths.
pub fn validate_container_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(BoxletError::InvalidContainerId {
            id: id.to_string(),
            reason: "container id must not be empty".to_string(),
        });
    }
    if id == "." || id == ".." || id.contains("..") {
        return Err(BoxletError::InvalidContainerId {
            id: id.to_string(),
            reason: "container id must not contain path traversal segments".to_string(),
        });
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(BoxletError::InvalidContainerId {
            id: id.to_string(),
            reason: "container id may only contain ASCII alphanumeric, '-', '_', or '.'"
                .to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_container_id_accepts_safe_ids_and_rejects_traversal() {
        assert!(validate_container_id("agent-01_test.v1").is_ok());
        assert!(validate_container_id("").is_err());
        assert!(validate_container_id("..").is_err());
        assert!(validate_container_id("../escape").is_err());
        assert!(validate_container_id("a/b").is_err());
    }

    #[test]
    fn load_bundle_spec_parses_valid_config_json() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: std::path::PathBuf::from("tempdir"),
            source,
        })?;
        let spec = Spec::default();
        spec.save(dir.path().join("config.json"))
            .map_err(|source| BoxletError::OciSpec {
                path: dir.path().join("config.json"),
                source,
            })?;

        let loaded = load_bundle_spec(dir.path())?;
        assert_eq!(loaded.version(), spec.version());
        Ok(())
    }

    #[test]
    fn bundle_builder_scaffolds_valid_config_and_rootfs_layout() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let dummy_bb = dir.path().join("fake-busybox");
        fs::write(&dummy_bb, b"#!/bin/sh\necho fake-bb\n").map_err(|source| {
            BoxletError::StateStore {
                path: dummy_bb.clone(),
                source,
            }
        })?;

        let bundle_dir = dir.path().join("my-bundle");
        let built = BundleBuilder::new()
            .with_shell_command("echo hello-bundle")
            .with_hostname("agent-node")
            .with_cwd("/tmp")
            .with_readonly_rootfs(true)
            .with_busybox(&dummy_bb)
            .build(&bundle_dir)?;

        let reloaded = load_bundle_spec(&bundle_dir)?;
        assert_eq!(reloaded.version(), OCI_RUNTIME_VERSION);
        assert_eq!(reloaded.hostname().as_deref(), Some("agent-node"));
        assert_eq!(
            reloaded.root().as_ref().and_then(|r| r.readonly()),
            Some(true)
        );
        assert_eq!(
            reloaded
                .process()
                .as_ref()
                .and_then(|p| p.args().as_ref())
                .cloned(),
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hello-bundle".to_string()
            ])
        );
        assert_eq!(built.version(), reloaded.version());

        let etc_hostname =
            fs::read_to_string(bundle_dir.join("rootfs/etc/hostname")).map_err(|source| {
                BoxletError::StateStore {
                    path: bundle_dir.join("rootfs/etc/hostname"),
                    source,
                }
            })?;
        assert_eq!(etc_hostname, "agent-node\n");

        #[cfg(unix)]
        {
            let sh_link = fs::read_link(bundle_dir.join("rootfs/bin/sh")).map_err(|source| {
                BoxletError::StateStore {
                    path: bundle_dir.join("rootfs/bin/sh"),
                    source,
                }
            })?;
            assert_eq!(sh_link, PathBuf::from("/bin/busybox"));
        }

        Ok(())
    }

    #[test]
    fn bundle_builder_with_uid_gid_mapping_configures_user_namespace() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let bundle_dir = dir.path().join("rootless-bundle");
        let spec = BundleBuilder::new()
            .with_uid_gid_mapping(1000, 1000)
            .build(&bundle_dir)?;

        let linux = spec.linux().as_ref().ok_or_else(|| BoxletError::Runtime {
            subsystem: "test",
            message: "expected linux section in generated spec".to_string(),
        })?;
        let namespaces = linux
            .namespaces()
            .as_ref()
            .ok_or_else(|| BoxletError::Runtime {
                subsystem: "test",
                message: "expected namespaces in generated spec".to_string(),
            })?;
        assert!(namespaces
            .iter()
            .any(|ns| ns.typ() == LinuxNamespaceType::User));

        let uid_maps = linux
            .uid_mappings()
            .as_ref()
            .ok_or_else(|| BoxletError::Runtime {
                subsystem: "test",
                message: "expected uid_mappings in generated spec".to_string(),
            })?;
        assert_eq!(uid_maps.len(), 1);
        assert_eq!(uid_maps[0].container_id(), 0);
        assert_eq!(uid_maps[0].host_id(), 1000);
        assert_eq!(uid_maps[0].size(), 1);

        let gid_maps = linux
            .gid_mappings()
            .as_ref()
            .ok_or_else(|| BoxletError::Runtime {
                subsystem: "test",
                message: "expected gid_mappings in generated spec".to_string(),
            })?;
        assert_eq!(gid_maps.len(), 1);
        assert_eq!(gid_maps[0].container_id(), 0);
        assert_eq!(gid_maps[0].host_id(), 1000);
        assert_eq!(gid_maps[0].size(), 1);
        Ok(())
    }
}
