// binver.hpp — SBOM components from binary version strings (docs/engine-design.md).
//
// The firmware value-add: general-purpose SBOM tools are weakest on stripped
// embedded images where a component announces itself only as an in-binary
// version banner ("BusyBox v1.36.1", "OpenSSL 1.1.1n"). This is M2 anchor -> M3
// bounded-window regex over ELF files, keyed to a curated table that also
// supplies the CPE (co-derived alongside purl), so the Phase 3 CVE join can
// match the CPE-indexed C-library CVEs that dominate firmware. Fully offline.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "component.hpp"

namespace ft {

// Scan a file's bytes for known version banners. Returns one Component per
// distinct (name, version) found, source "binary-version", with purl + CPE from
// the curated table.
//
// By default the scan runs only on ELF input; non-ELF input returns {} because a
// version banner in arbitrary bytes (release notes, help text, a decompressed
// container blob that mirrors an ELF already in the tree) is noise. Set
// `scan_nonelf` to also scan non-ELF input, restricted to the distinctive-anchor
// signatures that are false-positive-safe on arbitrary bytes (VersionSig::raw_safe).
// The caller passes this only for a monolithic tree (no ELF member anywhere), so
// statically-linked components in proprietary-OS / RTOS single-image firmware are
// recovered without changing the result on any filesystem-based image. ELF input
// always scans the full signature table regardless of the flag.
std::vector<Component> scan_binver(std::span<const uint8_t> data, const std::string& origin_path,
                                   bool scan_nonelf = false);

// Scan any file for the Linux kernel banner ("Linux version X.Y.Z ...") and
// return a linux_kernel component (source "kernel-banner", CPE
// cpe:2.3:o:linux:linux_kernel). NOT ELF-gated: the banner lives in raw and
// decompressed kernel images that are not ELF at offset 0. The banner string is
// specific enough to avoid the false positives that keep the other sigs
// ELF-gated. No CVE auto-match (the kernel has far too many CVEs for the
// targeted NVD fetch, and version->CVE is noisy); the version + CPE is the value.
std::vector<Component> scan_kernel_version(std::span<const uint8_t> data,
                                           const std::string& origin_path);

// Scan any file for the U-Boot banner ("U-Boot 2019.04 (Apr ...)") and return a
// u-boot component (source "bootloader-banner", CPE cpe:2.3:a:denx:u-boot). NOT
// ELF-gated: u-boot images are usually raw (DTB/FIT/ARM boot blobs), not ELF at
// offset 0. Unlike the kernel, u-boot has a tractable CVE count, so its CPE is in
// binver_cpe_products() and the NVD/CPE join covers it.
std::vector<Component> scan_uboot_version(std::span<const uint8_t> data,
                                          const std::string& origin_path);

// The curated (cpe_vendor, cpe_product) pairs the tool can emit as CPEs. The NVD
// updater queries these products so the CVE join can match the CPE-keyed firmware
// CVEs. Covers the binver ELF signatures plus the non-ELF u-boot banner.
std::vector<std::pair<std::string, std::string>> binver_cpe_products();

}  // namespace ft
