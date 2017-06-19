# Rules

Rules provide the primary evaluation mechanism of whitelisting and blacklisting binaries with Santa on macOS. There are two types of rules: binary and certificate.

##### Binary Rules

Binary rules use the SHA-256 hash of the entire binary as an identifier. This is the most specific rule in Santa. Even the smallest change in the binary alters the SHA-256 hash, in turn the rule would then not apply.

##### Certificate Rules

Certificate rules are the SHA-256 fingerprint of an x509 leaf signing certificate. This is a powerful rule type that has a much broader reach than an individual binary rule . A signing certificate can sign any number of binaries. Whitelisting or blacklisting just a few key signing certificates can cover the bulk of an average user's binaries. The leaf signing certificate is the only part of the chain that is evaluated. Though the whole chain is available for viewing.

```sh
⇒  santactl fileinfo /Applications/Dropbox.app --key "Signing Chain"
Signing Chain:
     1. SHA-256             : 2a0417257348a20f96c9de0486b44fcc7eaeaeb7625b207591b8109698c02dd2
        SHA-1               : 86ec91f726ba9caa09665b2109c49117f0b93134
        Common Name         : Developer ID Application: Dropbox, Inc.
        Organization        : Dropbox, Inc.
        Organizational Unit : G7HH3F8CAK
        Valid From          : 2012/06/19 16:10:30 -0400
        Valid Until         : 2017/06/20 16:10:30 -0400

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

If you wanted to whitelist or blacklist all software signed with this perticular Dropbox signing certificate you would use the leaf SHA-256 fingerprint.

`2a0417257348a20f96c9de0486b44fcc7eaeaeb7625b207591b8109698c02dd2`

Santa does to evaluate the `Valid From` or `Valid Until` fields. Nor does it check the Certificate Revocation List (CRL) or the Online Certificate Status Protocol (OCSP) for revoked certificates. Adding rules for the certificate chain's intermediates or roots have no effect on binaries signing by a leaf. This is mainly because Santa ignores the chain and is only concerned with the leaf certificate's SHA-256 hash.

##### Rule Evaluation

When a process is trying to `exec()` santad retrieves information on the binary, including hashing the entire file and extracting the signing chain (if any). The hash and signing leaf cert is then passed through the [SNTPolicyProcessor](https://github.com/google/santa/blob/master/Source/santad/SNTPolicyProcessor.h). Rules are evaluated from most specific to least specific. First binary (either whitelist or blacklist), then certificate (either whitelist or blacklist). If no rules are found that apply, scopes are then searched. See the [scopes.md](scopes.md) document for more information on scopes.

You can use the `santactl fileinfo` command to check the status of any given binary on the filesystem.

###### Whitelisted with a Binary Rule 

```sh
⇒  santactl fileinfo /Applications/Hex\ Fiend.app --key Rule
Whitelisted (Binary)
```

###### Whitelisted with a Certificate Rule

```sh
⇒  santactl fileinfo /Applications/Safari.app --key Rule
Whitelisted (Certificate)
```

###### Blacklisted with a Binary Rule

```sh
⇒  santactl fileinfo /usr/bin/yes --key Rule
Blacklisted (Binary)
```

###### Blacklisted with a Certificate Rule

```sh
⇒  santactl fileinfo /Applications/Malware.app --key Rule
Blacklisted (Certificate)
```

You can also check arbitrary SHA-256 binary and certificate hashes for rules. The rule verb needs to be run with root privileges.

Here is checking the SHA-256 hash of `/usr/bin/yes`:

```sh
sudo santactl rule --check --sha256 $(openssl sha -sha256 /usr/bin/yes  | awk '{print $2}')
Blacklisted (Binary)
```

Here we are checking the SHA-256 hash of `/usr/bin/yes ` signing certificate:

```sh
⇒  sudo santactl rule --check --certificate --sha256 $(santactl fileinfo --cert-index 1 --key SHA-256 /usr/bin/yes)
Whitelisted (Certificate)
```

##### Built in rules

To avoid blocking any Apple system binaries or Santa binaries, santad will create 2 immutable certificate rules at startup.

* The signing certificate santad is signed with
* The signing certificate launchd is signed with

By creating these two rules at startup, Santa should never block critical Apple system binaries or other Santa components.