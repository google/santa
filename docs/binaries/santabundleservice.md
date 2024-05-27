---
parent: Binaries
---

# santabundleservice

The `santabundleservice` is a small launch daemon responsible for creating
non-execution events for the contents of a bundle. When an execution is blocked,
the `santabundleservice` is tasked with determining if the binary is part of a
bundle and, if so, locating other executables contained within that bundle.
Finally, the service is responsible for generating the
[bundle hash](#bundle-hash) and computing the hash of all found binaries.

## Bundle Identification

Bundle structures for macOS applications is a loosely defined structure and is
further complicated by supporting nested bundles for common scenarios (e.g. XPC
services, app extensions, etc.). `santabundleservice` applies some heuristics to
locate the highest ancestor bundle containing the blocked binary.

*   Example 1
    *   Binary: `/Applications/DVD Player.app/Contents/MacOS/DVD Player`
    *   Containing Bundle: `/Applications/DVD Player.app`
*   Example 2
    *   Binary:
        `/Applications/Safari.app/Contents/PlugIns/CacheDeleteExtension.appex/Contents/MacOS
        CacheDeleteExtension`
    *   Containing Bundle: `/Applications/Safari.app`
*   Example 3
    *   Binary: `/bin/launchctl`
    *   Containing Bundle: N/A

## Events

Once the containing bundle is identified, the directory tree is scanned for all
contained binaries. Pseudo-events are created for each entry. These events can
be sent to the sync server if requested.

## Bundle Hash

To compute the bundle hash, the found events are sorted by their file SHA-256
hash. The hashes are concatenated and then SHA-256 hashed. This is now a strong
indicator on what Mach-O executables were within the bundle at the time of scan.
This can then be verified by the sync server when deciding to generate rules.
