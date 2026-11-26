# ADR-010: Cgroup v2 `io.max` Block I/O Throttling and Multi-Layer OCI Image Layout v1.1.0
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Boxlet V6 introduced Seccomp user-space notification (`SECCOMP_RET_USER_NOTIF`) and deterministic single-layer POSIX USTAR `.tar` rootfs archives (`export_rootfs_tar` / `import_rootfs_tar`). Two production gaps remained for multi-tenant AI agent sandboxes:
1. **Block Device Bandwidth & IOPS Isolation (`io.max`):** While Boxlet already enforced Cgroup v2 `memory.max`, `memory.swap.max`, `cpu.max`, and `pids.max`, untrusted agent workloads could still saturate host NVMe/block storage throughput or IOPS via runaway read/write loops.
2. **Multi-Layer OCI Image Layouts & Whiteout Semantics:** Distributing agent environments as a single monolithic `.tar` rootfs forced full-image transfers even when only a small upper layer changed, and lacked OCI Image Layer whiteout semantics (`.wh.<name>` and `.wh..wh..opq`) required to represent deleted files and opaque replacement directories across layers.

## Decision
1. **Cgroup v2 `io.max` Per-Device Throttling (`IoMaxRule`):**
   - Extend `ResourcePolicy` with `io_max: Vec<IoMaxRule>`, where each `IoMaxRule` specifies a Linux block device `major:minor` pair (`major: u32`, `minor: u32`) and optional limits (`rbps`, `wbps`, `riops`, `wiops`).
   - Validate all `IoMaxRule` entries fail-closed in `ResourcePolicy::validate()`: at least one rate limit (`rbps`, `wbps`, `riops`, `wiops`) must be `Some(> 0)` and zero limits are rejected with `BoxletError::InvalidPolicy`.
   - Format each rule deterministically via `IoMaxRule::to_cgroup_line()` as `<major>:<minor> rbps=<val|max> wbps=<val|max> riops=<val|max> wiops=<val|max>` and write each line to `<cgroup_dir>/io.max` inside `CgroupV2Manager::apply_limits()` before moving the container init PID into `cgroup.procs`.
   - Expose `--io-max <MAJ:MIN:rbps=...,wbps=...,riops=...,wiops=...>` on `boxlet create` and `boxlet run`, and map rules into the OCI runtime specification `linux.resources.blockIO.throttleReadBpsDevice` / `throttleWriteBpsDevice` / `throttleReadIopsDevice` / `throttleWriteIopsDevice` arrays.
   - Extend `boxlet doctor` with a `cgroup_v2_io_controller` diagnostic probe inspecting `/sys/fs/cgroup/cgroup.controllers` for the `io` controller.

2. **Multi-Layer OCI Image Layout v1.1.0 Packing, Unpacking & Whiteout Semantics:**
   - Enhance `import_rootfs_tar` in `src/image.rs` to process OCI Image Layer whiteout markers during layer extraction without materializing the marker files themselves:
     - **Opaque directory whiteout (`.wh..wh..opq`):** Verifies the marker is a zero-byte regular file, validates parent path containment, recursively makes any read-only lower-layer subdirectories writable, and removes all existing children inside the target directory before upper-layer entries in that directory are extracted.
     - **Explicit entry whiteout (`.wh.<name>`):** Verifies the marker is a zero-byte regular file, validates `<name>` against traversal characters, and removes the corresponding lower-layer file, symlink, or directory tree from `target_rootfs`.
   - Provide `pack_oci_image_layout(layer_dirs, layout_dir, tag) -> Result<OciImageLayoutReport>` to export an ordered sequence of layer directories into `<layout_dir>/blobs/fnv1a64/<hex>.tar`, write `<layout_dir>/oci-layout` (`{"imageLayoutVersion":"1.0.0"}`), and write `<layout_dir>/index.json` with `OciLayerDescriptor` entries and a deterministic 64-bit FNV-1a `index_digest`.
   - Provide `unpack_oci_image_layout(layout_dir, target_rootfs) -> Result<OciImageLayoutReport>` to validate `oci-layout` and `index.json`, verify each layer blob's byte size, entry count, and 64-bit FNV-1a digest (`fnv1a64:<16-hex-digits>`) fail-closed before/after extraction, and apply all layers sequentially onto `target_rootfs`.
   - Expose `boxlet image pack` and `boxlet image unpack` CLI subcommands and record `ImagePack` and `ImageUnpack` events in the structured JSONL audit log.

## Alternatives Considered
- **Proportional I/O weights (`io.weight` / `io.bfq.weight`):** Rejected as the primary control because proportional weights require active contention and specific I/O schedulers (such as BFQ), whereas `io.max` enforces hard, deterministic bandwidth and IOPS ceilings on any Cgroup v2 block device.
- **External OCI image tools (`skopeo` / `umoci`):** Rejected to preserve Boxlet's zero-external-binary, pure-Rust dependency footprint and deterministic FNV-1a content addressing across Linux and macOS hosts.

## Consequences & Failure Modes
- **Fail-Closed Digest & Whiteout Enforcement:** Any tampered layer blob in `blobs/fnv1a64/<hex>.tar`, mismatched `size` or `entry_count`, non-zero-byte whiteout marker, or path-traversal attempt in layer paths or digests immediately aborts `unpack_oci_image_layout` with `BoxletError::StateStore` (`InvalidData` / `InvalidInput`).
- **Kernel Controller Availability:** Writing `io.max` requires the `io` controller to be enabled in the parent cgroup's `cgroup.subtree_control`; `CgroupV2Manager` enables `+io` alongside `+memory +cpu +pids` on parent cgroups and fails closed if `io_max` rules are requested on a host where `io.max` cannot be written.
