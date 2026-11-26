//! Pure-Rust POSIX USTAR `.tar` rootfs archive export and fail-closed import.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{BoxletError, Result};
use crate::snapshot::{EntryKind, TreeManifest};

/// Standard 512-byte POSIX USTAR block size.
const TAR_BLOCK_SIZE: usize = 512;

/// Maximum byte length of `name` and `linkname` fields in a base POSIX USTAR header.
const USTAR_MAX_NAME_LEN: usize = 100;

/// Maximum byte length of the `prefix` field in a POSIX USTAR header (`block[345..500]`).
const USTAR_MAX_PREFIX_LEN: usize = 155;

/// 64-bit FNV-1a offset basis.
const FNV1A_64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// 64-bit FNV-1a prime.
const FNV1A_64_PRIME: u64 = 0x0100_0000_01b3;

/// Metadata summary returned by [`export_rootfs_tar`] and [`import_rootfs_tar`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootfsArchiveReport {
    /// Path to the `.tar` archive file.
    pub archive_path: PathBuf,
    /// Path to the rootfs directory exported from or imported into.
    pub rootfs_path: PathBuf,
    /// Number of filesystem entries (files, directories, symlinks) processed.
    pub entry_count: usize,
    /// Total logical file payload bytes processed.
    pub total_file_bytes: u64,
    /// Deterministic 64-bit FNV-1a digest of the `.tar` archive stream.
    pub archive_fnv1a64: u64,
}

/// Streaming writer wrapper that computes a 64-bit FNV-1a digest over all written bytes.
struct HashingWriter<W> {
    inner: W,
    hash: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hash: FNV1A_64_OFFSET_BASIS,
        }
    }

    fn write_all_hashed(&mut self, buf: &[u8], path: &Path) -> Result<()> {
        self.inner
            .write_all(buf)
            .map_err(|source| BoxletError::StateStore {
                path: path.to_path_buf(),
                source,
            })?;
        for &byte in buf {
            self.hash ^= u64::from(byte);
            self.hash = self.hash.wrapping_mul(FNV1A_64_PRIME);
        }
        Ok(())
    }

    fn finish(mut self, path: &Path) -> Result<u64> {
        self.inner
            .flush()
            .map_err(|source| BoxletError::StateStore {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(self.hash)
    }
}

/// Exports `rootfs_dir` deterministically into a POSIX USTAR `.tar` archive at `archive_path`.
///
/// Entries are ordered lexicographically via [`TreeManifest::capture`], skipping `.boxlet_old_root`
/// and zeroing `uid`, `gid`, and `mtime` so identical directory trees produce identical `.tar`
/// streams and identical `archive_fnv1a64` digests.
pub fn export_rootfs_tar(rootfs_dir: &Path, archive_path: &Path) -> Result<RootfsArchiveReport> {
    let manifest = TreeManifest::capture(rootfs_dir)?;

    if let Some(parent) = archive_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| BoxletError::StateStore {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }

    ensure_archive_not_inside_rootfs(rootfs_dir, archive_path)?;
    let stage_path = staged_sibling_path(archive_path)?;

    let write_res = (|| -> Result<u64> {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let raw_file = opts
            .open(&stage_path)
            .map_err(|source| BoxletError::StateStore {
                path: stage_path.clone(),
                source,
            })?;
        let mut writer = HashingWriter::new(raw_file);

        for (rel_path, meta) in &manifest.entries {
            let name_str = normalize_rel_path_for_tar(rel_path, archive_path)?;
            let src_path = rootfs_dir.join(rel_path);

            let (typeflag, payload_size, linkname) = match meta.kind {
                EntryKind::File => (b'0', meta.size, String::new()),
                EntryKind::Directory => (b'5', 0u64, String::new()),
                EntryKind::Symlink => {
                    let target =
                        fs::read_link(&src_path).map_err(|source| BoxletError::StateStore {
                            path: src_path.clone(),
                            source,
                        })?;
                    let target_str = target.to_str().ok_or_else(|| BoxletError::StateStore {
                        path: src_path.clone(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "symlink target is not valid UTF-8 for POSIX USTAR header",
                        ),
                    })?;
                    if target_str.is_empty()
                        || target_str.len() > USTAR_MAX_NAME_LEN
                        || target_str.as_bytes().contains(&0)
                    {
                        return Err(BoxletError::StateStore {
                            path: src_path,
                            source: std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "symlink target exceeds 100-byte POSIX USTAR linkname limit",
                            ),
                        });
                    }
                    (b'2', 0u64, target_str.to_string())
                }
            };

            let header = build_ustar_header(
                &name_str,
                meta.mode & 0o0777,
                payload_size,
                typeflag,
                &linkname,
                archive_path,
            )?;
            writer.write_all_hashed(&header, archive_path)?;

            if meta.kind == EntryKind::File {
                let mut file = File::open(&src_path).map_err(|source| BoxletError::StateStore {
                    path: src_path.clone(),
                    source,
                })?;
                let mut copied: u64 = 0;
                let mut buf = [0u8; 8192];
                loop {
                    let n = file
                        .read(&mut buf)
                        .map_err(|source| BoxletError::StateStore {
                            path: src_path.clone(),
                            source,
                        })?;
                    if n == 0 {
                        break;
                    }
                    let remaining_expected = payload_size.saturating_sub(copied);
                    if (n as u64) > remaining_expected {
                        return Err(BoxletError::StateStore {
                            path: src_path,
                            source: std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "file size changed while exporting rootfs tar archive",
                            ),
                        });
                    }
                    writer.write_all_hashed(&buf[..n], archive_path)?;
                    copied = copied.saturating_add(n as u64);
                }
                if copied != payload_size {
                    return Err(BoxletError::StateStore {
                        path: src_path,
                        source: std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "file size changed while exporting rootfs tar archive",
                        ),
                    });
                }
                let rem = (copied as usize) % TAR_BLOCK_SIZE;
                if rem != 0 {
                    let pad = [0u8; TAR_BLOCK_SIZE];
                    writer.write_all_hashed(&pad[..TAR_BLOCK_SIZE - rem], archive_path)?;
                }
            }
        }

        // Write two 512-byte zero end-of-archive blocks.
        let eof_blocks = [0u8; TAR_BLOCK_SIZE * 2];
        writer.write_all_hashed(&eof_blocks, archive_path)?;
        writer.finish(archive_path)
    })();

    let archive_fnv1a64 = match write_res {
        Ok(digest) => digest,
        Err(err) => {
            let _ = fs::remove_file(&stage_path);
            return Err(err);
        }
    };

    if let Err(source) = fs::rename(&stage_path, archive_path) {
        let _ = fs::remove_file(&stage_path);
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source,
        });
    }

    let total_file_bytes = manifest
        .entries
        .values()
        .filter(|m| m.kind == EntryKind::File)
        .map(|m| m.size)
        .fold(0u64, u64::saturating_add);

    Ok(RootfsArchiveReport {
        archive_path: archive_path.to_path_buf(),
        rootfs_path: rootfs_dir.to_path_buf(),
        entry_count: manifest.entries.len(),
        total_file_bytes,
        archive_fnv1a64,
    })
}

/// Imports a POSIX USTAR `.tar` archive from `archive_path` into `target_rootfs`.
///
/// Enforces fail-closed path traversal checks (rejecting empty paths, leading `/`, `..`
/// segments, and symlinked ancestor directories) and restores directory permissions in
/// reverse depth order after all files and symlinks have been materialized.
pub fn import_rootfs_tar(archive_path: &Path, target_rootfs: &Path) -> Result<RootfsArchiveReport> {
    if !archive_path.is_file() {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "rootfs tar archive file does not exist",
            ),
        });
    }

    if let Ok(meta) = fs::symlink_metadata(target_rootfs) {
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(BoxletError::StateStore {
                path: target_rootfs.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "target rootfs path must not be a symlink or non-directory",
                ),
            });
        }
    } else {
        fs::create_dir_all(target_rootfs).map_err(|source| BoxletError::StateStore {
            path: target_rootfs.to_path_buf(),
            source,
        })?;
    }
    make_dir_writable(target_rootfs)?;

    let mut file = File::open(archive_path).map_err(|source| BoxletError::StateStore {
        path: archive_path.to_path_buf(),
        source,
    })?;

    let mut hash = FNV1A_64_OFFSET_BASIS;
    let mut entry_count: usize = 0;
    let mut total_file_bytes: u64 = 0;
    let mut dir_modes: Vec<(PathBuf, u32)> = Vec::new();
    let mut reached_eof_marker = false;

    let mut block = [0u8; TAR_BLOCK_SIZE];
    loop {
        let bytes_read = read_full_or_eof(&mut file, &mut block, archive_path)?;
        if bytes_read == 0 {
            break;
        }
        for &b in &block {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(FNV1A_64_PRIME);
        }

        if block.iter().all(|&b| b == 0) {
            reached_eof_marker = true;
            continue;
        }
        if reached_eof_marker {
            return Err(BoxletError::StateStore {
                path: archive_path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected non-zero tar block after end-of-archive marker",
                ),
            });
        }

        verify_ustar_header(&block, archive_path)?;
        let raw_name = parse_ustar_string(&block[0..100], archive_path)?;
        let raw_prefix = parse_ustar_string(&block[345..500], archive_path)?;
        let combined_name = if raw_prefix.is_empty() {
            raw_name.to_string()
        } else {
            let _ = validate_safe_tar_rel_path(raw_prefix, archive_path)?;
            let _ = validate_safe_tar_rel_path(raw_name, archive_path)?;
            format!("{}/{}", raw_prefix.trim_end_matches('/'), raw_name)
        };
        let rel_path = validate_safe_tar_rel_path(&combined_name, archive_path)?;
        let mode = parse_ustar_octal(&block[100..108], archive_path)? as u32 & 0o0777;
        let size = parse_ustar_octal(&block[124..136], archive_path)?;
        let typeflag = block[156];
        let linkname = parse_ustar_string(&block[157..257], archive_path)?.to_string();

        ensure_safe_parent_dirs(target_rootfs, &rel_path)?;
        let dst_path = target_rootfs.join(&rel_path);

        match typeflag {
            b'5' => {
                if size != 0 {
                    return Err(BoxletError::StateStore {
                        path: archive_path.to_path_buf(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "directory entry in tar archive must have zero payload size",
                        ),
                    });
                }
                if let Ok(meta) = fs::symlink_metadata(&dst_path) {
                    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                        return Err(BoxletError::StateStore {
                            path: dst_path,
                            source: std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "tar entry contains unsafe path traversal",
                            ),
                        });
                    }
                } else {
                    fs::create_dir(&dst_path).map_err(|source| BoxletError::StateStore {
                        path: dst_path.clone(),
                        source,
                    })?;
                }
                make_dir_writable(&dst_path)?;
                dir_modes.push((rel_path, mode));
                entry_count += 1;
            }
            b'0' | b'\0' => {
                let stage_path = staged_sibling_path(&dst_path)?;
                let extract_res = (|| -> Result<()> {
                    let mut out_file = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&stage_path)
                        .map_err(|source| BoxletError::StateStore {
                            path: stage_path.clone(),
                            source,
                        })?;

                    let mut remaining = size;
                    while remaining > 0 {
                        read_exact_block(&mut file, &mut block, archive_path)?;
                        for &b in &block {
                            hash ^= u64::from(b);
                            hash = hash.wrapping_mul(FNV1A_64_PRIME);
                        }
                        let to_write = (remaining as usize).min(TAR_BLOCK_SIZE);
                        out_file.write_all(&block[..to_write]).map_err(|source| {
                            BoxletError::StateStore {
                                path: stage_path.clone(),
                                source,
                            }
                        })?;
                        remaining -= to_write as u64;
                    }
                    drop(out_file);
                    set_mode_permissions(&stage_path, mode)?;
                    remove_existing_non_dir(&dst_path)?;
                    fs::rename(&stage_path, &dst_path).map_err(|source| BoxletError::StateStore {
                        path: dst_path.clone(),
                        source,
                    })
                })();
                if let Err(err) = extract_res {
                    let _ = fs::remove_file(&stage_path);
                    return Err(err);
                }
                total_file_bytes = total_file_bytes.saturating_add(size);
                entry_count += 1;
            }
            b'2' => {
                if size != 0 || linkname.is_empty() {
                    return Err(BoxletError::StateStore {
                        path: archive_path.to_path_buf(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid symlink entry in tar archive",
                        ),
                    });
                }
                remove_existing_non_dir(&dst_path)?;
                create_symlink(Path::new(&linkname), &dst_path)?;
                entry_count += 1;
            }
            other => {
                return Err(BoxletError::StateStore {
                    path: archive_path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!("unsupported POSIX USTAR entry typeflag '{}'", other as char),
                    ),
                });
            }
        }
    }

    if !reached_eof_marker {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated tar archive: missing zero end-of-archive block",
            ),
        });
    }

    dir_modes.sort_by(|(a, _), (b, _)| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then_with(|| b.cmp(a))
    });
    for (rel_dir, mode) in dir_modes {
        let dir_path = target_rootfs.join(rel_dir);
        set_mode_permissions(&dir_path, mode)?;
    }

    Ok(RootfsArchiveReport {
        archive_path: archive_path.to_path_buf(),
        rootfs_path: target_rootfs.to_path_buf(),
        entry_count,
        total_file_bytes,
        archive_fnv1a64: hash,
    })
}

fn ensure_archive_not_inside_rootfs(rootfs_dir: &Path, archive_path: &Path) -> Result<()> {
    let abs_rootfs = fs::canonicalize(rootfs_dir).map_err(|source| BoxletError::StateStore {
        path: rootfs_dir.to_path_buf(),
        source,
    })?;
    let archive_parent = match archive_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let abs_parent =
        fs::canonicalize(archive_parent).map_err(|source| BoxletError::StateStore {
            path: archive_parent.to_path_buf(),
            source,
        })?;
    let file_name = archive_path
        .file_name()
        .ok_or_else(|| BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "archive path must include a file name",
            ),
        })?;
    let abs_archive = abs_parent.join(file_name);
    if abs_archive.starts_with(&abs_rootfs) {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "archive_path must not be located inside rootfs_dir",
            ),
        });
    }
    Ok(())
}

fn staged_sibling_path(dst: &Path) -> Result<PathBuf> {
    let parent = match dst.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = dst
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".to_string());
    Ok(parent.join(format!(".{name}.boxlet-stage-{}", std::process::id())))
}

fn normalize_rel_path_for_tar(rel_path: &Path, archive_path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for comp in rel_path.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_str().ok_or_else(|| BoxletError::StateStore {
                    path: archive_path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "rootfs entry path is not valid UTF-8",
                    ),
                })?;
                if s.is_empty() || s == "." || s == ".." || s.as_bytes().contains(&0) {
                    return Err(BoxletError::StateStore {
                        path: archive_path.to_path_buf(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "rootfs entry path contains invalid component",
                        ),
                    });
                }
                parts.push(s);
            }
            _ => {
                return Err(BoxletError::StateStore {
                    path: archive_path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "rootfs entry path must be relative without traversal components",
                    ),
                });
            }
        }
    }
    let joined = parts.join("/");
    let _ = split_ustar_name_and_prefix(&joined, archive_path)?;
    Ok(joined)
}

fn split_ustar_name_and_prefix<'a>(
    full_path: &'a str,
    archive_path: &Path,
) -> Result<(&'a str, &'a str)> {
    if full_path.is_empty() {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tar entry name must not be empty",
            ),
        });
    }
    if full_path.len() <= USTAR_MAX_NAME_LEN {
        return Ok(("", full_path));
    }
    for (idx, ch) in full_path.char_indices() {
        if ch == '/' {
            let prefix = &full_path[..idx];
            let name = &full_path[idx + 1..];
            if !prefix.is_empty()
                && prefix.len() <= USTAR_MAX_PREFIX_LEN
                && !name.is_empty()
                && name.len() <= USTAR_MAX_NAME_LEN
            {
                return Ok((prefix, name));
            }
        }
    }
    Err(BoxletError::StateStore {
        path: archive_path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tar entry name exceeds POSIX USTAR 100-byte name + 155-byte prefix limit",
        ),
    })
}

fn build_ustar_header(
    full_name: &str,
    mode: u32,
    size: u64,
    typeflag: u8,
    linkname: &str,
    archive_path: &Path,
) -> Result<[u8; TAR_BLOCK_SIZE]> {
    let (prefix, name) = split_ustar_name_and_prefix(full_name, archive_path)?;
    if linkname.len() > USTAR_MAX_NAME_LEN {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tar symlink target exceeds 100-byte POSIX USTAR limit",
            ),
        });
    }

    let mut header = [0u8; TAR_BLOCK_SIZE];
    header[..name.len()].copy_from_slice(name.as_bytes());
    if !prefix.is_empty() {
        header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    }

    let mode_str = format!("{:07o}\0", mode & 0o0777);
    header[100..108].copy_from_slice(mode_str.as_bytes());
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");

    let size_str = format!("{size:011o}\0");
    if size_str.len() != 12 {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "file size exceeds POSIX USTAR 8 GiB octal field limit",
            ),
        });
    }
    header[124..136].copy_from_slice(size_str.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = typeflag;
    if !linkname.is_empty() {
        header[157..157 + linkname.len()].copy_from_slice(linkname.as_bytes());
    }
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    let checksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    let chk_str = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(chk_str.as_bytes());

    Ok(header)
}

fn verify_ustar_header(block: &[u8; TAR_BLOCK_SIZE], archive_path: &Path) -> Result<()> {
    if &block[257..262] != b"ustar" {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid tar header: missing POSIX USTAR magic",
            ),
        });
    }

    let stored_checksum = parse_ustar_octal(&block[148..156], archive_path)? as u32;
    let mut computed: u32 = 0;
    for (idx, &b) in block.iter().enumerate() {
        if (148..156).contains(&idx) {
            computed += u32::from(b' ');
        } else {
            computed += u32::from(b);
        }
    }

    if stored_checksum != computed {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid tar header checksum",
            ),
        });
    }
    Ok(())
}

fn parse_ustar_string<'a>(field: &'a [u8], archive_path: &Path) -> Result<&'a str> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end]).map_err(|_| BoxletError::StateStore {
        path: archive_path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tar header field contains non-UTF-8 bytes",
        ),
    })
}

fn parse_ustar_octal(field: &[u8], archive_path: &Path) -> Result<u64> {
    let raw = parse_ustar_string(field, archive_path)?;
    let trimmed = raw.trim_matches(|c: char| c == ' ' || c == '\0');
    if trimmed.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(trimmed, 8).map_err(|_| BoxletError::StateStore {
        path: archive_path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid octal value '{trimmed}' in tar header"),
        ),
    })
}

fn validate_safe_tar_rel_path(raw_name: &str, archive_path: &Path) -> Result<PathBuf> {
    let trimmed = raw_name.trim_end_matches('/');
    if trimmed.is_empty()
        || raw_name.starts_with('/')
        || raw_name.starts_with('\\')
        || raw_name.contains('\\')
    {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tar entry contains unsafe path traversal",
            ),
        });
    }

    let candidate = Path::new(trimmed);
    let mut normalized = PathBuf::new();
    for comp in candidate.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_str().unwrap_or("");
                if s.is_empty() || s == "." || s == ".." {
                    return Err(BoxletError::StateStore {
                        path: archive_path.to_path_buf(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "tar entry contains unsafe path traversal",
                        ),
                    });
                }
                normalized.push(seg);
            }
            Component::ParentDir
            | Component::RootDir
            | Component::CurDir
            | Component::Prefix(_) => {
                return Err(BoxletError::StateStore {
                    path: archive_path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "tar entry contains unsafe path traversal",
                    ),
                });
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tar entry contains unsafe path traversal",
            ),
        });
    }

    Ok(normalized)
}

fn ensure_safe_parent_dirs(target_rootfs: &Path, rel_path: &Path) -> Result<()> {
    let mut cursor = target_rootfs.to_path_buf();
    if let Some(parent) = rel_path.parent() {
        for comp in parent.components() {
            if let Component::Normal(seg) = comp {
                cursor.push(seg);
                match fs::symlink_metadata(&cursor) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                            return Err(BoxletError::StateStore {
                                path: cursor,
                                source: std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "tar entry contains unsafe path traversal",
                                ),
                            });
                        }
                        make_dir_writable(&cursor)?;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        fs::create_dir(&cursor).map_err(|source| BoxletError::StateStore {
                            path: cursor.clone(),
                            source,
                        })?;
                    }
                    Err(source) => {
                        return Err(BoxletError::StateStore {
                            path: cursor,
                            source,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

fn remove_existing_non_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_dir() {
                return Err(BoxletError::StateStore {
                    path: path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "cannot overwrite existing directory with non-directory tar entry",
                    ),
                });
            }
            fs::remove_file(path).map_err(|source| BoxletError::StateStore {
                path: path.to_path_buf(),
                source,
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(BoxletError::StateStore {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_full_or_eof(
    file: &mut File,
    buf: &mut [u8; TAR_BLOCK_SIZE],
    archive_path: &Path,
) -> Result<usize> {
    let mut offset = 0;
    while offset < TAR_BLOCK_SIZE {
        let n = file
            .read(&mut buf[offset..])
            .map_err(|source| BoxletError::StateStore {
                path: archive_path.to_path_buf(),
                source,
            })?;
        if n == 0 {
            if offset == 0 {
                return Ok(0);
            }
            return Err(BoxletError::StateStore {
                path: archive_path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated 512-byte block in tar archive",
                ),
            });
        }
        offset += n;
    }
    Ok(offset)
}

fn read_exact_block(
    file: &mut File,
    buf: &mut [u8; TAR_BLOCK_SIZE],
    archive_path: &Path,
) -> Result<()> {
    let n = read_full_or_eof(file, buf, archive_path)?;
    if n != TAR_BLOCK_SIZE {
        return Err(BoxletError::StateStore {
            path: archive_path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading tar entry payload block",
            ),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn make_dir_writable(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|source| BoxletError::StateStore {
        path: path.to_path_buf(),
        source,
    })?;
    let current_mode = meta.permissions().mode() & 0o7777;
    if current_mode & 0o700 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(current_mode | 0o700)).map_err(
            |source| BoxletError::StateStore {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_dir_writable(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|source| BoxletError::StateStore {
        path: path.to_path_buf(),
        source,
    })?;
    let mut perms = meta.permissions();
    if perms.readonly() {
        perms.set_readonly(false);
        fs::set_permissions(path, perms).map_err(|source| BoxletError::StateStore {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode_permissions(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o0777)).map_err(|source| {
        BoxletError::StateStore {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_mode_permissions(path: &Path, mode: u32) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|source| BoxletError::StateStore {
        path: path.to_path_buf(),
        source,
    })?;
    let mut perms = meta.permissions();
    perms.set_readonly(mode & 0o200 == 0);
    fs::set_permissions(path, perms).map_err(|source| BoxletError::StateStore {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn create_symlink(target: &Path, link_path: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link_path).map_err(|source| BoxletError::StateStore {
        path: link_path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, link_path: &Path) -> Result<()> {
    Err(BoxletError::StateStore {
        path: link_path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlinks require a Unix host filesystem",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_and_import_rootfs_tar_roundtrips_manifest_identically() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let original = tmp.path().join("original-rootfs");
        let imported = tmp.path().join("imported-rootfs");
        let archive_path = tmp.path().join("images/rootfs.tar");

        fs::create_dir_all(original.join("bin")).map_err(|source| BoxletError::StateStore {
            path: original.join("bin"),
            source,
        })?;
        fs::create_dir_all(original.join("etc/conf.d")).map_err(|source| {
            BoxletError::StateStore {
                path: original.join("etc/conf.d"),
                source,
            }
        })?;
        fs::create_dir_all(original.join(".boxlet_old_root")).map_err(|source| {
            BoxletError::StateStore {
                path: original.join(".boxlet_old_root"),
                source,
            }
        })?;

        fs::write(original.join("bin/busybox"), b"#!/bin/sh\necho busybox\n").map_err(
            |source| BoxletError::StateStore {
                path: original.join("bin/busybox"),
                source,
            },
        )?;
        set_mode_permissions(&original.join("bin/busybox"), 0o755)?;

        fs::write(original.join("etc/conf.d/app.toml"), b"workers = 4\n").map_err(|source| {
            BoxletError::StateStore {
                path: original.join("etc/conf.d/app.toml"),
                source,
            }
        })?;
        set_mode_permissions(&original.join("etc/conf.d"), 0o555)?;

        fs::write(
            original.join(".boxlet_old_root/ignored.txt"),
            b"must not export",
        )
        .map_err(|source| BoxletError::StateStore {
            path: original.join(".boxlet_old_root/ignored.txt"),
            source,
        })?;

        #[cfg(unix)]
        create_symlink(Path::new("/bin/busybox"), &original.join("bin/sh"))?;

        let export_report = export_rootfs_tar(&original, &archive_path)?;
        let import_report = import_rootfs_tar(&archive_path, &imported)?;

        // Restore write bit on original/etc/conf.d and imported/etc/conf.d after capturing manifests
        let orig_manifest = TreeManifest::capture(&original)?;
        let imp_manifest = TreeManifest::capture(&imported)?;

        set_mode_permissions(&original.join("etc/conf.d"), 0o755)?;
        set_mode_permissions(&imported.join("etc/conf.d"), 0o755)?;

        assert_eq!(orig_manifest, imp_manifest);
        assert!(orig_manifest.diff(&imp_manifest).is_empty());
        assert_eq!(export_report.entry_count, import_report.entry_count);
        assert_eq!(
            export_report.total_file_bytes,
            import_report.total_file_bytes
        );
        assert_eq!(export_report.archive_fnv1a64, import_report.archive_fnv1a64);
        assert!(!imported.join(".boxlet_old_root").exists());

        Ok(())
    }

    #[test]
    fn import_rootfs_tar_rejects_path_traversal_entries() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(|source| BoxletError::StateStore {
            path: PathBuf::from("tempdir"),
            source,
        })?;
        let archive_path = tmp.path().join("malicious.tar");
        let target_rootfs = tmp.path().join("sub/target-rootfs");
        let escape_file = tmp.path().join("sub/escape.txt");

        let payload = b"owned\n";
        let header = build_ustar_header(
            "../escape.txt",
            0o644,
            payload.len() as u64,
            b'0',
            "",
            &archive_path,
        )?;
        let mut block = [0u8; TAR_BLOCK_SIZE];
        block[..payload.len()].copy_from_slice(payload);
        let eof = [0u8; TAR_BLOCK_SIZE * 2];

        let mut tar_bytes = Vec::new();
        tar_bytes.extend_from_slice(&header);
        tar_bytes.extend_from_slice(&block);
        tar_bytes.extend_from_slice(&eof);
        fs::write(&archive_path, &tar_bytes).map_err(|source| BoxletError::StateStore {
            path: archive_path.clone(),
            source,
        })?;

        let res = import_rootfs_tar(&archive_path, &target_rootfs);
        assert!(matches!(
            res,
            Err(BoxletError::StateStore { ref source, .. })
                if source.kind() == std::io::ErrorKind::InvalidInput
        ));
        assert!(!escape_file.exists());

        // Also reject nested archive inside rootfs_dir and truncated archive missing EOF zero block
        let nested_rootfs = tmp.path().join("nested-rootfs");
        fs::create_dir_all(&nested_rootfs).map_err(|source| BoxletError::StateStore {
            path: nested_rootfs.clone(),
            source,
        })?;
        assert!(export_rootfs_tar(&nested_rootfs, &nested_rootfs.join("inside.tar")).is_err());

        let truncated_archive = tmp.path().join("truncated.tar");
        let valid_header = build_ustar_header(
            "etc/ok.txt",
            0o644,
            payload.len() as u64,
            b'0',
            "",
            &truncated_archive,
        )?;
        let mut trunc_bytes = Vec::new();
        trunc_bytes.extend_from_slice(&valid_header);
        trunc_bytes.extend_from_slice(&block);
        fs::write(&truncated_archive, &trunc_bytes).map_err(|source| BoxletError::StateStore {
            path: truncated_archive.clone(),
            source,
        })?;
        assert!(import_rootfs_tar(&truncated_archive, &target_rootfs).is_err());

        Ok(())
    }
}
