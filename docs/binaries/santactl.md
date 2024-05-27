---
parent: Binaries
---

# santactl

`santactl` is a command line utility for interacting with Santa. It provides the
following commands:

*   [`status`](#status): Viewing Santa status and configuration
*   [`version`](#version): View version information
*   [`fileinfo`](#fileinfo): Inspect individual files and see how Santa would
    apply policy
*   [`rule`](#rule): If a sync server isn't configured, can be used to manually
    manage rules
*   [`sync`](#sync): Trigger an immediate sync operation
*   [`printlog`](#printlog): Printing protobuf logs as JSON

## status

To view the status of Santa run `santactl status`

```sh
⇒  santactl status
>>> Daemon Info
  Mode                      | Lockdown
  Transitive Rules          | Yes
  Log Type                  | protobuf
  File Logging              | Yes
  USB Blocking              | Yes
  USB Remounting Mode       | noexec, rdonly
  On Start USB Options      | ForceRemount
  Watchdog CPU Events       | 0  (Peak: 2.19%)
  Watchdog RAM Events       | 0  (Peak: 29.45MB)
>>> Cache Info
  Root cache count          | 123
  Non-root cache count      | 0
>>> Database Info
  Binary Rules              | 123
  Certificate Rules         | 45
  TeamID Rules              | 6
  SigningID Rules           | 78
  CDHash Rules              | 0
  Compiler Rules            | 5
  Transitive Rules          | 321
  Events Pending Upload     | 0
>>> Static Rules
  Rules                     | 5
>>> Watch Items
  Enabled                   | Yes
  Policy Version            | v11.1
  Rule Count                | 6
  Config Path               | /var/db/santa/file_access_config.plist
  Last Policy Update        | 2024/05/21 22:36:42 -0400
>>> Sync Info
  Sync Server               | https://sync-server.com/santa/
  Clean Sync Required       | No
  Last Successful Full Sync | 2024/05/24 07:59:19 -0400
  Last Successful Rule Sync | 2024/05/24 08:49:06 -0400
  Push Notifications        | Connected
  Bundle Scanning           | Yes
>>> Metrics Info
  Metrics Server            | http://localhost/submit
  Export Interval (seconds) | 30
```

The `status` command can print JSON output via `santactl status --json`

## version

To view all of the component versions run `santactl version`

```sh
⇒  santactl version
santad          | 2024.4 (build 622252801)
santactl        | 2024.4 (build 622252801)
SantaGUI        | 2024.4 (build 622252801)
```

The `version` command can print JSON output via `santactl status --json`

## fileinfo

The `fileinfo` verb is very powerful and can be used to tease out just about
anything you wish to know about a file, with respect to the domain of Santa.

Here is an example of using `santactl fileinfo` to inspect the main executable
within `/Applications/Hex Fiend.app`.

```sh
⇒  santactl fileinfo /Applications/Hex\ Fiend.app
Path                   : /Applications/Hex Fiend.app/Contents/MacOS/Hex Fiend
SHA-256                : 1e265633a11675570aa6ddc916a53699f8914bf71d3e20ecac99c5a62b0f5652
SHA-1                  : 5667bc35b1a49a6c2a4829f4f0708b7cfd993a0b
Bundle Name            : Hex Fiend
Bundle Version         : 1655090551
Bundle Version Str     : 2.16
Team ID                : QK92QP33YN
Signing ID             : QK92QP33YN:com.ridiculousfish.HexFiend
CDHash                 : 449eab7814085ec1600edd27fdedc7dc08b41658
Type                   : Executable (arm64, x86_64)
Code-signed            : Yes
Rule                   : Allowed (Binary)
Signing Chain:
    1. SHA-256             : a1a9c87ecd87323023c6012cab59d5412be9679b7e405ad53b185c4a66da3688
       SHA-1               : c810baa43157e4a07e396b82c9bc0e9af46681ee
       Common Name         : Developer ID Application: Kevin Wojniak (QK92QP33YN)
       Organization        : Kevin Wojniak
       Organizational Unit : QK92QP33YN
       Valid From          : 2017/10/02 20:44:52 -0400
       Valid Until         : 2022/10/03 20:44:52 -0400

    2. SHA-256             : 7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f
       SHA-1               : 3b166c3b7dc4b751c9fe2afab9135641e388e186
       Common Name         : Developer ID Certification Authority
       Organization        : Apple Inc.
       Organizational Unit : Apple Certification Authority
       Valid From          : 2012/02/01 17:12:15 -0500
       Valid Until         : 2027/02/01 17:12:15 -0500

    3. SHA-256             : b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024
       SHA-1               : 611e5b662c593a08ff58d14ae22452d198df6c60
       Common Name         : Apple Root CA
       Organization        : Apple Inc.
       Organizational Unit : Apple Certification Authority
       Valid From          : 2006/04/25 17:40:36 -0400
       Valid Until         : 2035/02/09 16:40:36 -0500
```

Any of the desired information can be targeted with one or more instances of the
`--key` flag:

```sh
⇒  santactl fileinfo /Applications/Hex\ Fiend.app --key SHA-256 --key Rule
SHA-256: 1e265633a11675570aa6ddc916a53699f8914bf71d3e20ecac99c5a62b0f5652
Rule   : Allowed (Binary)
```

Multiple files can be specified simultaneously:

```sh
⇒  santactl fileinfo /bin/* --key SHA-256 --key Path
SHA-256: a47c5a87b7d359bd59558ebbf94c0ca88bceb37e60aa25a3d9077f814e1968c5
Path   : /bin/cat

SHA-256: deddb05a52aa228c8b9a04a4f82fea187dc51a612c6e1cf8e446008a98ed09f1
Path   : /bin/date

SHA-256: a32c631171b07cf89603735194cfdf56277af4e4dd06fc01fdf6747376cb1946
Path   : /bin/dash

SHA-256: 76bd512291ad0eee227de9c3b7026b78003c369f76d32cecc0311d8ea75b341e
Path   : /bin/df

SHA-256: d1837a1a87823a3930f6888329dd794c06a266a922cdd003f0f09ac11187e3a3
Path   : /bin/dd

... Additional items omitted ...
```

The `--recursive` flag can be used for lookups of an application or directory:

```sh
⇒  santactl fileinfo --recursive /Applications/Santa.app --key Path --key Type
Path: /Applications/Santa.app/Contents/CodeResources
Type: Unknown

Path: /Applications/Santa.app/Contents/_CodeSignature/CodeResources
Type: Unknown

Path: /Applications/Santa.app/Contents/MacOS/Santa
Type: Executable (arm64, x86_64)

Path: /Applications/Santa.app/Contents/MacOS/santametricservice
Type: Executable (arm64, x86_64)

Path: /Applications/Santa.app/Contents/MacOS/santasyncservice
Type: Executable (arm64, x86_64)

... Additional items omitted ...
```

The `--bundleinfo` flag can be used to display the bundle hash and the hash of
all binaries contained within the bundle:

```sh
⇒  santactl fileinfo --bundleinfo /System/Applications/Calendar.app
Path                   : /System/Applications/Calendar.app/Contents/MacOS/Calendar
... Common fileinfo information displayed above omitted here for brevity ...
Bundle Info:
       Main Bundle Path    : /System/Applications/Calendar.app
       Main Bundle ID      : com.apple.iCal
       Bundle Hash         : 3ae28266bb80f1462b488cdcd4c1489a16bee6392fa5bcb6ed90736e06ff5520
              66b54163340f9eeb1ff1882c9d43b44a32e8b6bf4318d491fe8bfcc0c247e922  /System/Applications/Calendar.app/Contents/PlugIns/FaceTimeExtension.appex/Contents/MacOS/FaceTimeExtension
              b3b191df22d096c7a66043598fb9bdff594321d4ab35a9428d2b3143154c9046  /System/Applications/Calendar.app/Contents/PlugIns/CalendarNotificationContentExtension_OSX.appex/Contents/MacOS/CalendarNotificationContentExtension_OSX
              359b3cdcf47645537a0c4090ab75428c6f3e7faf7e94773af05389dbba183e77  /System/Applications/Calendar.app/Contents/PlugIns/CalendarWidgetExtension.appex/Contents/MacOS/CalendarWidgetExtension
              921bf9a45e8d63d7fd8ac6b9b62a9239112c849243725b3d156598c6ccce8fe8  /System/Applications/Calendar.app/Contents/Extensions/CalendarFocusConfigurationExtension.appex/Contents/MacOS/CalendarFocusConfigurationExtension
              15507e8790bedd738c528364123268b5cabe43861e0c3e149bbad96e712c5c4a  /System/Applications/Calendar.app/Contents/MacOS/Calendar
```

The `fileinfo` command can print JSON output via `santactl status --json`

## rule

The rule command is covered in the [Rules](../concepts/rules.md) document.

## sync

The sync command triggers an immediate full sync. More details on syncing are
covered in the [Syncing Overview](../introduction/syncing-overview.md) document.

```sh
⇒  santactl sync
```

By default, syncing will insert/update newly received rules. This command
supports two flags: `--clean` and `--clean-all`, both will request a clean sync
from the sync server. If the server fulfilled the clean sync operation, usage of
the `--clean` flag will result in all non-transitive rules being removed from
the database before applying the newly received rules. The `--clean-all` flag
will result in all previously existing rules first being removed.

## printlog

If Santa is configured to use protobuf logging, this command can be used on the
resultant log files to print the contents as JSON.

```sh
⇒  santactl printlog /path/to/santa/protobuf/log
[
  [
    {
      "event_time": "2024-05-24T15:48:03.570141358Z",
      "processed_time": "2024-05-24T15:48:03.765921Z",
      "fork": {
        "instigator": {
          "id": {
            "pid": 45035,
            "pidversion": 3871292
          },
          ...
```
