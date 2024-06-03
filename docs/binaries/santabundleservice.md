---
parent: Binaries
---

# santabundleservice

The `santabundleservice` is a small daemon responsible for creating
non-execution events for the contents of a bundle. When an execution is blocked,
the `santabundleservice` is tasked with determining if the binary is part of a
bundle and, if so, locating other executables contained within that bundle.
Finally, the service is responsible for generating the
[bundle hash](#bundle-hash) and creating [events](#events) for all found
binaries.

## Bundle Identification

macOS application bundles are formed by a directory with a
[loosely-defined structure](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html).
Bundles may also contain nested bundles (e.g. XPC services, app extensions,
etc.). `santabundleservice` applies some heuristics to locate the highest
ancestor bundle containing the blocked binary.

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
contained binaries. Pseudo-events are created for each entry that contain all of
the same information as normal [execution events](../concepts/events.md). These
events can be sent to the sync server if requested.

## Bundle Hash

To compute the bundle hash, the found events are sorted by their file SHA-256
hash. The hashes are concatenated and then SHA-256 hashed. This is a strong
indicator of what Mach-O executables were within the bundle at the time of scan.
The sync server can then verify the hashes when deciding to generate rules.
