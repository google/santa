# santabs

The santabs process is an XPC service for the santa-driver.kext bundle, meaning only binaries within that bundle can launch santabs. It will be launched with the same privileges as its calling process. Currently, santad is the only caller of santabs, so santabs runs as root.

##### Events

The santabs process is quite simple and only does one thing: it generates non-execution events for the contents of a bundle.

When there is an `execve()` that is blocked within a bundle, a few actions take place:

1. The highest ancestor bundle in the tree is found

   * So `/Applications/DVD Player.app/Contents/MacOS/DVD Player` would be `/Applications/DVD Player.app`
   * Or `/Applications/Safari.app/Contents/PlugIns/CacheDeleteExtension.appex/Contents/MacOS/CacheDeleteExtension` would be `/Applications/Safari.app`

2. The ancestor bundle is then searched for Mach-O executables

   * For Safari that would currently be 4 binaries

   * ```sh
     Hashing time: 53 ms
     4 events found
     BundleHash: 718773556ca5ea798f984fde2fe1a5994f175900b26d2964c9358a0f469a4ac6
     BundleID: com.apple.Safari
     	SHA-256: ea872e83a518ce442ed050c4408a448d915e2bae90ef8455ce7805448d864a3e
     	Path: /Applications/Safari.app/Contents/PlugIns/CacheDeleteExtension.appex/Contents/MacOS/CacheDeleteExtension
     BundleID: com.apple.Safari
     	SHA-256: 1a43283857b1822164f82af274c476204748c0a2894dbcaa11ed17f78e0273cc
     	Path: /Applications/Safari.app/Contents/MacOS/Safari
     BundleID: com.apple.Safari
     	SHA-256: ab0ac54dd90144931b681d1e84e198c6510be44ac5339437bc004e60777af7ba
     	Path: /Applications/Safari.app/Contents/Resources/appdiagnose
     BundleID: com.apple.Safari
     	SHA-256: f49c5aa3a7373127d0b4945782b1fa375dd3707d66808fd66b7c0756430defa8
     	Path: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.BrowserDataImportingService.xpc/Contents/MacOS/com.apple.Safari.BrowserDataImportingService
     ```

3. Events are created for each binary and the bundle hash is calculated

4. These events are sent to the sync server for processing

##### Bundle Hash

The found events are sorted by their file SHA-256 hash. The hashes are concatenated and then SHA-256 hashed. This is now a strong indicator on what Mach-O executables were within the bundle at the time of scan. This can then be verified by the sync server when deciding to generate rules.