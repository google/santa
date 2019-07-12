# Mode

Santa can run in one of two modes, Lockdown or Monitor. To check the current status run the following command:

```sh
⇒  santactl status
>>> Daemon Info
  Mode                      | Monitor
  File Logging              | Yes
  Watchdog CPU Events       | 0  (Peak: 13.59%)
  Watchdog RAM Events       | 0  (Peak: 31.49MB)
>>> Kernel Info
  Root cache count          | 107
  Non-root cache count      | 0
>>> Database Info
  Binary Rules              | 5
  Certificate Rules         | 2
  Events Pending Upload     | 0
>>> Sync Info
  Sync Server               | https://sync-server-hostname.com
  Clean Sync Required       | No
  Last Successful Full Sync | 2017/08/02 21:44:17 -0400
  Last Successful Rule Sync | 2017/08/02 21:44:17 -0400
  Push Notifications        | Connected
  Bundle Scanning           | Yes
```

##### Monitor mode

The default mode. Running Santa in Monitor Mode will stop any binaries matching blacklist rules, but will not stop unknown binaries from running. This is a flexible state, allowing virtually zero user interruption but still gives protection against known blacklisted binaries. In addition execution events that would have been blocked in Lockdown mode are generated and can be collected and analyzed by a sync server.

##### Lockdown mode

Running Santa in Lockdown Mode will stop all blacklisted binaries and additionally will prevent all unknown binaries from running. This means that if the binary has no rules or scopes that apply, then it will be blocked.

##### Changing Modes

There are two ways to change the running mode: changing the configuration profile and with a sync server configuration.

###### Change modes with the configuration profile

Set the `ClientMode` in your configuration profile to the integer value `1` for MONITOR or `2` for LOCKDOWN.

```xml
<key>ClientMode</key>
<integer>1</integer>
```

Install your new configuration profile, it will overwrite any old `com.google.santa` profiles you may have already install. See the [configuration](../deployment/configuration.md) document for more details.

###### Change modes with a sync server

The mode is set in the preflight sync stage. Use the key `client_mode` and a value of `MONITOR` or `LOCKDOWN`.
