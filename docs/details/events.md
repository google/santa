# Events

Events are a defined set of data, core to how Santa interacts with a sync
server. Events are generated when there is a blocked `execve()` while in
Lockdown or Monitor mode. Events are also generated in Monitor mode for an
`execve()` that was allowed to run, but would have been blocked in Lockdown
mode. This allows an admin to roll out Santa to their macOS fleet in Monitor
mode but still collect meaningful data. The events collected while in Monitor
mode can be used to build a reasonably comprehensive allowlist of signing
certificates and binaries before switching the fleet to Lockdown mode.

##### Event Data

Events begin their life as an
[SNTStoredEvent](https://github.com/google/santa/blob/master/Source/common/SNTStoredEvent.h)
object. The SNTStoredEvent class is just a simple storage class that has
properties for all the relevant bits of information. More importantly the class
implements the
[NSSecureCoding](https://developer.apple.com/documentation/foundation/nssecurecoding?language=objc)
protocol. This allows the objects to be encoded and decoded for storage in the
events sqlite3 database on disk and sent over XPC to another process.

Events are temporarily stored in a database until they are uploaded. The format
is subject the change; accessing the events database directly will most likely
break in future releases. If direct access to the events database is required,
raise a [issue on the Santa GitHub](https://github.com/google/santa/issues).

###### JSON

Before an event is uploaded to a sync server, the event data is copied into a
JSON blob. Here is an example of Firefox being blocked and sent for upload:

```json
{
  "events": [
    {
      "file_path": "/var/folders/l5/pd9rhsp54s79_9_qcy746_tw00b_4p/T/AppTranslocation/254C1357-7461-457B-B734-A0FDAF0F26D9/d/Firefox.app/Contents/MacOS",
      "file_bundle_version": "5417.6.28",
      "parent_name": "launchd",
      "logged_in_users": [
        "bur"
      ],
      "quarantine_timestamp": 0,
      "signing_chain": [
        {
          "cn": "Developer ID Application: Mozilla Corporation (43AQ936H96)",
          "valid_until": 1652123338,
          "org": "Mozilla Corporation",
          "valid_from": 1494270538,
          "ou": "43AQ936H96",
          "sha256": "96f18e09d65445985c7df5df74ef152a0bc42e8934175a626180d9700c343e7b"
        },
        {
          "cn": "Developer ID Certification Authority",
          "valid_until": 1801519935,
          "org": "Apple Inc.",
          "valid_from": 1328134335,
          "ou": "Apple Certification Authority",
          "sha256": "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f"
        },
        {
          "cn": "Apple Root CA",
          "valid_until": 2054670036,
          "org": "Apple Inc.",
          "valid_from": 1146001236,
          "ou": "Apple Certification Authority",
          "sha256": "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
        }
      ],
      "file_bundle_name": "Firefox",
      "executing_user": "bur",
      "ppid": 1,
      "file_bundle_path": "/var/folders/l5/pd9rhsp54s79_9_qcy746_tw00b_4p/T/AppTranslocation/254C1357-7461-457B-B734-A0FDAF0F26D9/d/Firefox.app",
      "file_name": "firefox",
      "execution_time": 1501691337.059514,
      "file_sha256": "dd78f456a0929faf5dcbb6d952992d900bfdf025e1e77af60f0b029f0b85bf09",
      "decision": "BLOCK_BINARY",
      "file_bundle_id": "org.mozilla.firefox",
      "file_bundle_version_string": "54.0.1",
      "pid": 49368,
      "current_sessions": [
        "bur@console",
        "bur@ttys000",
        "bur@ttys001",
        "bur@ttys002",
        "bur@ttys003",
        "bur@ttys004"
      ]
    }
  ]
}
```

##### Event Lifecycle

1.  santad generates a new event
2.  santad compares, or adds if not present, the event's SHA-256 file hash to an
    in-memory cache with a timeout of 10 min. If an event with an matching hash
    is present in cache, the event is dropped.
3.  santad saves the event to `/var/db/santa/events.db` with a unique ID
    assigned as the key.
4.  santad sends an XPC message to the santactl daemon. The message contains the
    event with instructions to upload the event immediately. This is
    non-blocking and is performed on a background thread.

##### Bundle Events

Bundle events are a special type of event that are generated when a sync server
supports receiving the associated bundle events, instead of just the original
event. For example: `/Applications/Keynote.app/Contents/MacOS/Keynote` is
blocked and an event representing the binary is uploaded. An allow rule is
created for that one binary. Great, you can now run
`/Applications/Keynote.app/Contents/MacOS/Keynote`, but what about all the other
supporting binaries contained in the bundle? You would have to wait until they
are executed until an event would be generated. It is very common for a bundle
to contain multiple binaries, as shown here with Keynote.app. Waiting to get a
block is not a very good user experience.

```sh
⇒  santactl bundleinfo /Applications/Keynote.app
Hashing time: 1047 ms
9 events found
BundleHash: b475667ab1ab6eddea48bfc2bed76fcef89b8f85ed456c8068351292f7cb4806
BundleID: com.apple.iWork.Keynote
    SHA-256: be3aa404ee79c2af863132b93b0eedfdbc34c6e35d4fda2ade6dd637692ead84
    Path: /Applications/Keynote.app/Contents/XPCServices/com.apple.iWork.MovieCompatibilityConverter.xpc/Contents/MacOS/com.apple.iWork.MovieCompatibilityConverter
BundleID: com.apple.iWork.Keynote
    SHA-256: 3b2582fd5e7652b653276b3980c248dc973e8082e9d0678c96a08d7d1a8366ba
    Path: /Applications/Keynote.app/Contents/XPCServices/com.apple.iWork.PICTConverter.xpc/Contents/MacOS/com.apple.iWork.PICTConverter
BundleID: com.apple.iWork.Keynote
    SHA-256: f1bf3be05d511d7c7f651cf7b130d4977f8d28d0bfcd7c5de4144b95eaab7ad7
    Path: /Applications/Keynote.app/Contents/XPCServices/com.apple.iWork.ExternalResourceAccessor.xpc/Contents/XPCServices/com.apple.iWork.TCMovieExtractor.xpc/Contents/MacOS/com.apple.iWork.TCMovieExtractor
BundleID: com.apple.iWork.Keynote
    SHA-256: b59bc8548c91088a40d9023abb5d22fa8731b4aa17693fcb5b98c795607d219a
    Path: /Applications/Keynote.app/Contents/XPCServices/com.apple.iWork.BitmapTracer.xpc/Contents/MacOS/com.apple.iWork.BitmapTracer
BundleID: com.apple.iWork.Keynote
    SHA-256: 08cb407f541d867f1a63dc3ae44eeedd5181ca06c61df6ef62b5dc7192951a4b
    Path: /Applications/Keynote.app/Contents/XPCServices/com.apple.iWork.TCUtilities32.xpc/Contents/MacOS/com.apple.iWork.TCUtilities32
BundleID: com.apple.iWork.Keynote
    SHA-256: b965ae7be992d1ce818262752d0cf44297a88324a593c67278d78ca4d16fcc39
    Path: /Applications/Keynote.app/Contents/XPCServices/com.apple.iWork.ExternalResourceAccessor.xpc/Contents/XPCServices/com.apple.iWork.TCMovieExtractor.xpc/Contents/XPCServices/com.apple.iWork.TCMovieExtractor.TCUtilities32.xpc/Contents/MacOS/com.apple.iWork.TCMovieExtractor.TCUtilities32
BundleID: com.apple.iWork.Keynote
    SHA-256: 59668dc27314f0f6f5daa5f02b564c176f64836c88e2dfe166e90548f47336f1
    Path: /Applications/Keynote.app/Contents/MacOS/Keynote
BundleID: com.apple.iWork.Keynote
    SHA-256: 7ce324f919b14e14d327004b09f83ca81345fd4438c87ead4b699f89e9485595
    Path: /Applications/Keynote.app/Contents/XPCServices/com.apple.iWork.ExternalResourceAccessor.xpc/Contents/XPCServices/com.apple.iWork.ExternalResourceValidator.xpc/Contents/MacOS/com.apple.iWork.ExternalResourceValidator
BundleID: com.apple.iWork.Keynote
    SHA-256: 6b47f551565d886388eeec5e876b6de9cdd71ef36d43b0762e6ebf02bdd8515d
    Path: /Applications/Keynote.app/Contents/XPCServices/com.apple.iWork.ExternalResourceAccessor.xpc/Contents/MacOS/com.apple.iWork.ExternalResourceAccessor
```

Bundle events provide a mechanism to generate and upload events for all the
executable Mach-O binaries within a bundle. To enable bundle event generation a
configuration must be set in the preflight sync stage on the sync server. Once
set the sync server can use bundle events to drive a better user experience.

Bundle events can be differentiated by the existence of these fields:

| Field                    | Value                                           |
| ------------------------ | ----------------------------------------------- |
| decision                 | BUNDLE_BINARY                                   |
| file_bundle_hash         | Super Hash of all binary hashes                 |
| file_bundle_hash_millis  | The time in milliseconds it took to find all of |
|                          | the binaries, hash and produce a super hash     |
| file_bundle_binary_count | Number of binaries within the bundle            |

To avoid redundant uploads of a bundle event Santa will wait for the sync server
to ask for them. The server will respond to event uploads with a request like
this:

| Field                        | Value                                   |
| ---------------------------- | --------------------------------------- |
| event_upload_bundle_binaries | An array of bundle hashes that the sync |
|                              | server needs to be uploaded             |

When santactl receives this type of request, it sends an XPC reply to santad to
save all the bundle events to the events.db. It then attempts to upload all the
bundle events, purging the successes from the events.db. Any failures will be
uploaded during the next full sync.
