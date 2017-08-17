# santactl

This may be the most complex part of Santa. It does two types of work:

1. It contains all of the code and functionality for syncing with a sync-server.
2. It can be used to view the state and configuration of Santa as a whole. It can also inspect individual files. When running without a sync server it also a supported method of managing the rules database.

The details of santactl's syncing functionality are covered in the syncing.md document. This document will cover the status work that santactl performs.

##### status

To view the status of Santa run `santactl status`

```sh
⇒  santactl status
>>> Daemon Info
  Mode                      | Monitor
  File Logging              | Yes
  Watchdog CPU Events       | 0  (Peak: 2.19%)
  Watchdog RAM Events       | 0  (Peak: 29.45MB)
>>> Kernel Info
  Kernel cache count        | 123
>>> Database Info
  Binary Rules              | 321
  Certificate Rules         | 123
  Events Pending Upload     | 0
>>> Sync Info
  Sync Server               | https://sync-server.com/santa/
  Clean Sync Required       | No
  Last Successful Full Sync | 2017/08/10 15:05:32 -0400
  Last Successful Rule Sync | 2017/08/10 15:29:21 -0400
  Push Notifications        | Connected
  Bundle Scanning           | Yes
```

The status command also has the ability to print JSON output `santactl status --json`

```sh
⇒  santactl status --json
{
  "kernel" : {
    "cache_count" : 123
  },
  "daemon" : {
    "watchdog_ram_events" : 0,
    "watchdog_ram_peak" : 29.44921875,
    "watchdog_cpu_events" : 0,
    "file_logging" : true,
    "mode" : "Monitor",
    "watchdog_cpu_peak" : 2.188006666666666
  },
  "database" : {
    "events_pending_upload" : 0,
    "certificate_rules" : 123,
    "binary_rules" : 321
  },
  "sync" : {
    "last_successful_rule" : "2017\/08\/10 15:29:21 -0400",
    "push_notifications" : "Connected",
    "bundle_scanning" : true,
    "clean_required" : false,
    "server" : "https:\/\//sync-server.com\/santa\/",
    "last_successful_full" : "2017\/08\/10 15:05:32 -0400"
  }
}
```

##### version

To view all of the component versions `santactl version`

```sh
⇒  santactl version
santa-driver    | 0.9.19
santad          | 0.9.19
santactl        | 0.9.19
SantaGUI        | 0.9.19
```

Again, a JSON version is available `santactl version --json`

```sh
⇒  santactl version --json
{
  "santa-driver" : "0.9.19",
  "santad" : "0.9.19",
  "SantaGUI" : "0.9.19",
  "santactl" : "0.9.19"
}
```

##### fileinfo

The fileinfo verb is very powerful and can be used to tease out just about anything you wish to know about a file, with respect to the domain of Santa.

Here is an example of using `santactl fileinfo ` to inspect the main executable within `/Applications/Hex Fiend.app`. 

```sh
⇒  santactl fileinfo /Applications/Hex\ Fiend.app
Path                 : /Applications/Hex Fiend.app/Contents/MacOS/Hex Fiend
SHA-256              : efaf88db065beae61615f6f176c11c751555d2bad3c5da6cdad71635896014f1
SHA-1                : 5585e6fb94eace1bd37da9a0a2f928e992d7c60c
Bundle Name          : Hex Fiend
Bundle Version       : 170205
Bundle Version Str   : 2.5
Download Referrer URL: http://ridiculousfish.com/hexfiend/
Download URL         : http://ridiculousfish.com/hexfiend/files/Hex_Fiend_2.5.dmg
Download Timestamp   : 2017/06/29 12:52:16 -0400
Download Agent       : com.google.Chrome
Type                 : Executable (x86-64)
Code-signed          : Yes
Rule                 : Whitelisted (Unknown)
Signing Chain:
     1. SHA-256             : ba1be5d2d60a43658a0c6ebf61b577e428439b53ef2e0b96ba90285e2c82a1b2
        SHA-1               : 8fdbf6d6c22a97c472fb4961b7733ab0d8830ff7
        Common Name         : Developer ID Application: Kevin Wojniak
        Organization        : Kevin Wojniak
        Organizational Unit : QK92QP33YN
        Valid From          : 2012/10/30 01:07:40 -0400
        Valid Until         : 2017/10/31 01:07:40 -0400

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

Any of the desired information can be targeted with the `--key` flag

```sh
⇒  santactl fileinfo /Applications/Hex\ Fiend.app --key SHA-256
efaf88db065beae61615f6f176c11c751555d2bad3c5da6cdad71635896014f1
```

Multiple `--key` flags are allowed

```sh
⇒  santactl fileinfo /Applications/Hex\ Fiend.app --key SHA-256 --key Rule
efaf88db065beae61615f6f176c11c751555d2bad3c5da6cdad71635896014f1
Whitelisted (Unknown)
```

The `--json` flag can also be used at any point

```sh
⇒  santactl fileinfo /Applications/Hex\ Fiend.app --key SHA-256 --key Rule --json
{
  "SHA-256" : "efaf88db065beae61615f6f176c11c751555d2bad3c5da6cdad71635896014f1",
  "Rule" : "Whitelisted (Unknown)"
}
```

Multiple files are also supported as input

```sh
⇒  santactl fileinfo /bin/* --key SHA-256 --key Rule --json
[
{
  "SHA-256" : "5d8e161c21fc1a43374c4cf21be05360dbe2ecea0165fd4725ae7a958f2a0b02",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "295fbc2356e8605e804f95cb6d6f992335e247dbf11767fe8781e2a7f889978a",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "9f9b36ec79b9fcaf649e17f2f94c544dd408c2ab630e73d7c62a7a43f1bc7b1d",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "08a09d2d9bade16872acdf5da1c4e9d29582ed985480a9e73fd389e98293c40d",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "48e4b938b363201ec11d06a13d8080c1bd77187d286780259b9304c96edc5324",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "7dff6291a29fdaf97dad64c0671dc5d1ecc42189bc5daf8ca08e2a3ae06aff95",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "7cbba457df4c02d6a7fb93046fea0e869732c65a2225bee6f2e8ec290d38c57b",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "39e894d1705656451f592884a56bcc76e7ffbb9ed2a8b81d5f2878e1c0e68dbe",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "8555ed4622410aa7b4379041acabf80fe452a90efe3be2697406935ff0d6822e",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "cee3e29089f8919ee904328904a7492995cfa398b027857fbf8b3e601397b308",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "da2cfa9fc2cabd41907f9d0931cea79000a19520fe0b3d73fc40537408730e40",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "73aee02c4761e5501b1fdfa51ccd316bf735017a5cc0a09d5bcc46f4e7112be9",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "3a1c4ca5a038b42b1fbfca6f9bec25d307a8af40afbe9c48b307372fe8167a2f",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "9dc8e1c5b6ec49602dd968eb88286e330220233f7cfa6e73fd37fc983a365084",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "78fd9b8749c2a216ca76ff4541754d4cf5a5e2e8c00710a85c3fdab171486f92",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "c4daaf12bd42adee60549872126e15186c75d89e760f078bfa6a45a861f6400f",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "9dba1cbb01bce47a9610a40cbcbc27704a754e31a889503eb0670c3a25f7ad72",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "a5ae86cd413589d9661fc604349fb153c0d6f5dfa3d9e95e01b8bc5e09bc1da1",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "a5ae86cd413589d9661fc604349fb153c0d6f5dfa3d9e95e01b8bc5e09bc1da1",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "c4c5517ff40a33006028853a19734d8cda8e2942cb9ba27b8310e07f18677487",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "a944b104742db59204b45f1dae657bd6a845ff2374e1ade3cf9f09cc428154cf",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "09e143cf3b6c4dcc98676cc45543613b83b6527b502d4dacb42b3f6c7036ef5a",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "47cea771e93aff464f1060a6a1a2c3855401e6cd22c3971b2b76fae92e8c33b4",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "5682f15628ae15e5c29aa37f19ec421bbe4aca47734864b6363b73a16f891888",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "83c29a2445d84daf51eebd51668753fb39600a136efc20aba7298a812b44974c",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "83929910d3cd2c401636337fadc747a9a8ea6c174bfd80f1e96b99d877ddfa6e",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "cccd818698aa802b116586a773643d0b951067dea8284304acaae62ac97b362b",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "2bf2d10a7529a88d340ce0255da52dbef9873ccb44e46d23af03abf70b8e54ca",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "956f2dc7ba31663dd3a9b70e84e6a2491980165426b90cacd10db4bd010c3353",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "da1a3ae959751b211928f175f6c8987408a976be44690022c92d45ef5a8cb6e5",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "1e51209ae4549a72432ad504341c0731a282b33ba99c5f7f4e2abc9993e09b0a",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "7dff6291a29fdaf97dad64c0671dc5d1ecc42189bc5daf8ca08e2a3ae06aff95",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "5d8e161c21fc1a43374c4cf21be05360dbe2ecea0165fd4725ae7a958f2a0b02",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "83929910d3cd2c401636337fadc747a9a8ea6c174bfd80f1e96b99d877ddfa6e",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "17372eafbe9e920d5715a9cffa59f881ef4ed949785c1e2adf9c067d550dbde6",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "b1834d55b76c65d57cef1219a30331452301e84b6e315f2a17e5b5b295ce1648",
  "Rule" : "Whitelisted (Certificate)"
}
]
```

Recursive lookups of an application or directory is a soon to be added feature

```sh
⇒  santactl fileinfo --recursive /Applications/Santa.app --key SHA-256 --key Rule --key Type --json
[
{
  "SHA-256" : "c149c10c83abaf6b602401106f098b68d47a1a433ab02455cef2ca8057cf4a82",
  "Type" : "Unknown",
  "Rule" : "Whitelisted (Scope)"
},
{
  "SHA-256" : "c339c3e5e04c732ae493dbc4a26d18fccc8bb48cea0cc0762ccd8754ef318a0b",
  "Type" : "Unknown",
  "Rule" : "Whitelisted (Scope)"
},
{
  "SHA-256" : "6ee757ab65d7c93e8b6a467b44cd2f0d10b6db7da8b6200e778c3ca279ea5619",
  "Type" : "Executable (x86-64)",
  "Rule" : "Whitelisted (Certificate)"
},
{
  "SHA-256" : "82502191c9484b04d685374f9879a0066069c49b8acae7a04b01d38d07e8eca0",
  "Type" : "Unknown",
  "Rule" : "Whitelisted (Scope)"
},
{
  "SHA-256" : "9814019f865a540d3635012a75db932eaefc9a62468750f2294350690430aadf",
  "Type" : "Unknown",
  "Rule" : "Whitelisted (Scope)"
},
{
  "SHA-256" : "05a9c9dbbf0a7a30f083e3dccd8db3d96845e0644930977b4e284c65083b89ac",
  "Type" : "Unknown",
  "Rule" : "Whitelisted (Scope)"
},
{
  "SHA-256" : "e1db8fdffc5017684f962c51fad059dcaa06ab5d551186aa85711f80b727d23d",
  "Type" : "Unknown",
  "Rule" : "Whitelisted (Scope)"
}
]
```

##### rule

The rule command is covered in the [rules.md](rules.md) document.

##### sync

The sync command is covered in the [syncing.md](syncing.md) document.

##### Debug Commands

There are a few commands that are not included in the release versions of Santa. They are mainly used during development and only accessible with a debug build of Santa.

##### bundleinfo

This prints info about all of the executable Mach-O files within a bundle. It also prints the calculated bundle hash for that particular bundle. A bundle hash is a notion used by Santa to represent a set of binaries.

```sh
⇒  santactl bundleinfo /Applications/Hex\ Fiend.app
Hashing time: 12 ms
4 events found
BundleHash: 33da3e2d5e2ccbdb9d34fb9753c2c18805e6325853d2fb4eb947915c90113efc
BundleID: com.ridiculousfish.HexFiend
	SHA-256: e592a7c65f803675c0b7d55ab7d2a1a2696c9f097a99dc28a4083d7387e53d95
	Path: /Applications/Hex Fiend.app/Contents/Library/LaunchServices/com.ridiculousfish.HexFiend.PrivilegedHelper
BundleID: com.ridiculousfish.HexFiend
	SHA-256: ce23d39a1a8ff2b42baad5a0204b24b57590bb7ff74c9552b3ba10d9c1517279
	Path: /Applications/Hex Fiend.app/Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Autoupdate.app/Contents/MacOS/Autoupdate
BundleID: com.ridiculousfish.HexFiend
	SHA-256: efaf88db065beae61615f6f176c11c751555d2bad3c5da6cdad71635896014f1
	Path: /Applications/Hex Fiend.app/Contents/MacOS/Hex Fiend
BundleID: com.ridiculousfish.HexFiend
	SHA-256: 148d6ae55176b619e5eb9f5000922b3ca4c126206fc5782f925d112027f9db3c
	Path: /Applications/Hex Fiend.app/Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Autoupdate.app/Contents/MacOS/fileop
```

See the [santabs.md](santabs.md) document for more information on bundles and bundle hashes.

##### checkcache

This is used to check if a particular file is apart of santa-driver's kernel cache. Mainly for debugging purposes.

```sh
⇒  santactl checkcache /usr/bin/yes
File does not exist in cache
⇒  /usr/bin/yes
y
y
y
y
y
^C
⇒  santactl checkcache /usr/bin/yes
File exists in [whitelist] kernel cache
```

##### flushcache

This can be used to flush santa-driver's kernel cache, as shown here.

```sh
⇒  santactl checkcache /usr/bin/yes
File exists in [whitelist] kernel cache
⇒  sudo santactl flushcache
Cache flush requested
⇒  santactl checkcache /usr/bin/yes
File does not exist in cache
```
