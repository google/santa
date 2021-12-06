---
title: Troubleshooting
parent: Deployment
---

# Troubleshooting

As kernel extensions have been considered deprecated for several OS releases,
this page will cover troublshooting the system extension and related topics. 

## Confirming Status

While there's an entire page on [santactl](../details/santactl.md), it's one of the best ways to start 
determining the cause of an issue:

```sh
/usr/local/bin/santactl status
```

Conveniently, the order the information is displayed may indicate the likelihood
of commonly experienced issues:

- In the first section, if "Driver Connected" does not read Yes, start by
confirming the MDM is considered 'supervising' the computer via DEP or UAMDM,
(see [configuration.md](configuration.md)) this command would help:

```sh
/usr/bin/profiles status -type enrollment
```

The profile payloads that rely on the supervision relationship cannot be applied
manually for testing, so it's important to ensure the MDM connection is as
expected when mass-deploying.

- Additionally, confirm the system extension and TCC/PPPC profiles are present
as mentioned under the ["MDM-Specific Client Configuration"](configuration.md) section of that page
- If there is no "Cache Info" section, the EnableSysxCache key may not
be present in the payload configuring Santa or the framework applying the key
locally may not have properly loaded it into the applicable domain. You can
confirm its presence or absence with the following command:

```sh
sudo /usr/bin/profiles -L -o stdout-xml | grep -A1 EnableSysxCache
```

- The local preferences would dictate the sync server used as well, and the
next sections help you confirm how many rules have in fact been recognized by
Santa as well as its details and live connection state

## Confirming Actions

Looking into [logs](../details/logs.md) would be instructive for the majority
of how Santa is operating, and the pages on [scopes](../details/scopes.md) and [rules](../details/rules.md) would assist in
determining precendence and why decisions are made. Most helpful is the output of
`/usr/local/bin/santactl`'s `fileinfo` verb when called with the path/binary in
question as described on the [santactl](../details/santactl.md) page.

Depending on the presence or implementation details of a sync server, there may
be queues and a process for allowing binaries or updated developer certificates.
Events may also be observable from the server