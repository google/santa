---
parent: Concepts
---

# Mode

Santa can run in one of two modes, Lockdown or Monitor. To check the current
mode, use the `santactl status` command, for example:

```sh
⇒  santactl status | grep "^  Mode"
  Mode                      | Lockdown
```

##### Monitor mode

The default mode. Running Santa in Monitor Mode will stop any binaries matching
block rules, but will not stop unknown binaries from running. This is a flexible
state, allowing virtually zero user interruption but still gives protection
against known blocked binaries. In addition execution events that would have
been blocked in Lockdown mode are generated and can be collected and analyzed by
a sync server.

##### Lockdown mode

Running Santa in Lockdown Mode will stop all blocked binaries and additionally
will prevent all unknown binaries from running. This means that if the binary
has no rules or scopes that apply, then it will be blocked.

##### Changing Modes

There are two ways to change the running mode: changing the configuration
profile and with a sync server configuration.

###### Change modes with the configuration profile

Set the `ClientMode` in your configuration profile to the integer value `1` for
MONITOR or `2` for LOCKDOWN.

```xml
<key>ClientMode</key>
<integer>1</integer>
```

Install your new configuration profile, it will overwrite any old
`com.google.santa` profiles you may have already install. See the
[configuration](../deployment/configuration.md) document for more details.

###### Change modes with a sync server

The mode is set in the preflight sync stage. Use the key `client_mode` and a
value of `MONITOR` or `LOCKDOWN`.
