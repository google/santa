---
parent: Concepts
---

# Rules

## Rule Types

Rules provide the primary evaluation mechanism for allowing and blocking
binaries with Santa on macOS. There are four types of rules: binary, signing ID,
certificate, and Team ID.

### Binary Rules

Binary rules use the SHA-256 hash of the entire binary as an identifier. This is
the most specific rule in Santa. Even a small change in the binary will alter
the SHA-256 hash, invalidating the rule.

### Signing ID Rules

Signing IDs are arbitrary identifiers under developer control that are given to
a binary at signing time. Typically, these use reverse domain name notation and
include the name of the binary (e.g. `com.google.Chrome`). Because the signing
IDs are arbitrary, the Santa rule identifier must be prefixed with the Team ID
associated with the Apple developer certificate used to sign the application.
For example, a signing ID rule for Google Chrome would be:
`EQHXZ8M8AV:com.google.Chrome`. For platform binaries (i.e. those binaries
shipped by Apple with the OS) which do not have a Team ID, the string `platform`
must be used (e.g. `platform:com.apple.curl`).

### Certificate Rules

Certificate rules are formed from the SHA-256 fingerprint of an X.509 leaf
signing certificate. This is a powerful rule type that has a much broader reach
than an individual binary rule. A signing certificate can sign any number of
binaries. Allowing or blocking just a few key signing certificates can cover the
bulk of an average user's binaries. The leaf signing certificate is the only
part of the chain that is evaluated. Though the whole chain is available for
viewing.

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

If you wanted to allow or block all software signed with this particular Dropbox
signing certificate you would use the leaf SHA-256 fingerprint.

`2a0417257348a20f96c9de0486b44fcc7eaeaeb7625b207591b8109698c02dd2`

Santa does not evaluate the `Valid From` or `Valid Until` fields, nor does it
check the Certificate Revocation List (CRL) or the Online Certificate Status
Protocol (OCSP) for revoked certificates. Adding rules for the certificate
chain's intermediates or roots has no effect on binaries signing by a leaf.
Santa ignores the chain and is only concerned with the leaf certificate's
SHA-256 hash.

### Apple Developer Team ID Rules

The Apple Developer Program Team ID is a 10-character identifier issued by Apple
and tied to developer accounts/organizations. This is distinct from Certificates,
as a single developer account can and frequently will request/rotate between
multiple different signing certificates and entitlements. This is an even more
powerful rule with broader reach than individual certificate rules.

## Rule Evaluation

When a process is trying to execute, `santad` retrieves information on the
binary, including a hash of the entire file, signing ID, the signing chain (if
any), and the team ID. The collected info is then passed through the
[SNTPolicyProcessor](https://github.com/google/santa/blob/master/Source/santad/SNTPolicyProcessor.h).

Rules (both ALLOW and BLOCK) are evaluated in the following order, from most
specific to least specific:

```
Most Specific                                  Least Specific

Binary   -->   Signing ID   -->   Certificate   -->   Team ID
```

If no rules are found that apply, scopes are then searched. See the
[scopes.md](scopes.md) document for more information on scopes.

### Rule Examples

You can use the `santactl fileinfo` command to check the status of any given
binary on the filesystem.

#### Allowed with a Binary Rule

```sh
⇒  santactl fileinfo /Applications/Hex\ Fiend.app --key Rule
Allowed (Binary)
```

#### Allowed with a Signing ID Rule

```sh
⇒  santactl fileinfo /Applications/Example.app --key Rule
Allowed (SigningID)
```

#### Allowed with a Certificate Rule

```sh
⇒  santactl fileinfo /Applications/Safari.app --key Rule
Allowed (Certificate)
```

#### Allowed with a Team ID rule

```sh
⇒ santactl fileinfo /Applications/Spotify.app --key Rule
Allowed (TeamID)
```

For checking the Team ID of `/Applications/Microsoft\ Remote\ Desktop.app`

```sh
⇒  santactl fileinfo /Applications/Spotify.app --key "Team ID"
2FNC3A47ZF
```

#### Blocked with a Binary Rule

```sh
⇒  santactl fileinfo /usr/bin/yes --key Rule
Blocked (Binary)
```

#### Blocked with a Signing ID Rule

```sh
⇒  santactl fileinfo /Applications/Example.app --key Rule
Blocked (SigningID)
```

#### Blocked with a Certificate Rule

```sh
⇒  santactl fileinfo /Applications/Malware.app --key Rule
Blocked (Certificate)
```

You can also check arbitrary SHA-256 binary and certificate hashes for rules.
The rule verb needs to be run with root privileges.

For checking the SHA-256 hash of `/usr/bin/yes`:

```sh
sudo santactl rule --check --sha256 $(santactl fileinfo --key SHA-256 /usr/bin/yes)
Blocked (Binary)
```

For checking the SHA-256 hash of `/usr/bin/yes` signing certificate:

```sh
⇒  sudo santactl rule --check --certificate --sha256 $(santactl fileinfo --cert-index 1 --key SHA-256 /usr/bin/yes)
Allowed (Certificate)
```

#### Blocked with a Team ID rule

```sh
⇒ santactl fileinfo /Applications/Microsoft\ Remote\ Desktop.app --key Rule
Blocked (TeamID)
```

For checking the Team ID of `/Applications/Microsoft\ Remote\ Desktop.app`

```sh
⇒  santactl fileinfo /Applications/Microsoft\ Remote\ Desktop.app --key "Team ID"
UBF8T346G9
```

### Built-in rules

To avoid blocking any Apple system binaries or Santa binaries, `santad` will
create 2 immutable certificate rules at startup:

*   The signing certificate santad is signed with
*   The signing certificate launchd is signed with

By creating these two rules at startup, Santa should never block critical Apple
system binaries or other Santa components.
