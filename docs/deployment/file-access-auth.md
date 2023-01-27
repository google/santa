---
title: File Access Authorization
parent: Deployment
nav_order: 4
---

# (BETA) File Access Authorization

> **IMPORTANT:** This feature is in beta. Configuration and log formats are subject to change.

> **IMPORTANT:** This feature is only supported on macOS 13 and above.

File Access Authorization allows admins to configure Santa to monitor filesystem paths for potentially unwanted access and optionally deny the operation.

## Enabling the Feature

To enable this feature, the `FileAccessPolicyPlist` key in the main [Santa configuration](configuration.md) must contain the path to a configuration file. See the format specified in the [Configuration](#configuration) section below. The Santa configuration can also contain the `FileAccessPolicyUpdateIntervalSec` that dictates how often the File Access Authorization configuration is re-applied (see the details on [Path Globs](#path-globs) for more information on what happens during updates).

## Configuration
<!-- Note: Non-breaking spaces used to hack the column width since otherwise the description is unreadable. -->
| Key                 | Parent       | Type       | Required | Default    | Description&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; |
| ------------------- | ------------ | ---------- | -------- | ---------- | ----------- |
| `Version`           | `<Root>`     | String     | Yes      | N/A        | Version of the configuration. Will be reported in events. |
| `WatchItems`        | `<Root>`     | Dictionary | No       | N/A        | The set of configuration items that will be monitored by Santa. |
| `<Name>`            | `WatchItems` | Dictionary | No       | N/A        | A unique name that identifies a single watch item rule. This value will be reported in events. The name must be a legal C identifier (e.g., must conform to the regex `[A-Za-z_][A-Za-z0-9_]*`). |
| `Paths`             | `<Name>`     | Array      | Yes      | N/A        | A list of either String or Dictionary types that contain path globs to monitor. String type entires will have default values applied for the attributes that can be manually set with the Dictionary type. |
| `Path`              | `Paths`      | String     | Yes      | None       | The path glob to monitor. |
| `IsPrefix`          | `Paths`      | Boolean    | No       | False      | Whether or not the path glob represents a prefix path. |
| `Options`           | `<Name>`     | Dictionary | No       | N/A        | Customizes the actions for a given rule. |
| `AllowReadAccess`   | `Options`    | Boolean    | No       | False      | If true, indicates the rule will **not** be applied to actions that are read-only access (e.g., opening a watched path for reading, or cloning a watched path). If false, the rule will apply both to read-only access and access that could modify the watched path. |
| `AuditOnly`         | `Options`    | Boolean    | No       | True       | If true, operations violating the rule will only be logged. If false, operations violating the rule will be denied and logged. |
| `Processes`         | `<Name>`     | Array      | No       | N/A        | A list of dictionaries defining processes that are allowed to access paths matching the globs defined with the `Paths` key. For a process performing the operation to be considered a match, it must match all defined attributes of at least one entry in the list. |
| `BinaryPath`        | `Processes`  | String     | No       | None       | A path literal that an instigating process must be executed from. |
| `TeamID`            | `Processes`  | String     | No       | None       | Team ID of the instigating process. |
| `CertificateSha256` | `Processes`  | String     | No       | None       | SHA256 of the leaf certificate of the instigating process. |
| `CDHash`            | `Processes`  | String     | No       | None       | CDHash of the instigating process. |


### Example Configuration

This is an example configuration conforming to the specification outlined above:

```plist
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Version</key>
	<string>v0.1-experimental</string>
	<key>WatchItems</key>
	<dict>
		<key>UserFoo</key>
		<dict>
			<key>Paths</key>
			<array>
				<string>/Users/*/foo</string>
				<dict>
					<key>Path</key>
					<string>/Users/*/tmp/foo</string>
					<key>IsPrefix</key>
					<true/>
				</dict>
			</array>
			<key>Options</key>
			<dict>
				<key>AllowReadAccess</key>
				<false/>
				<key>AuditOnly</key>
				<true/>
			</dict>
			<key>Processes</key>
			<array>
				<dict>
					<key>BinaryPath</key>
					<string>/usr/local/bin/my_foo_writer</string>
					<key>TeamID</key>
					<string>ABCDEF1234</string>
				</dict>
			</array>
		</dict>
	</dict>
</dict>
</plist>
```

## Details

### Rule Matching

When an operation occurs on a path that matches multiple configured path globs, the rule containing the "most specific" matching path glob is applied (i.e., the longest matching path).

For example, consider the configured rules and paths:
```
RULE_1: /tmp/foo     [IsPrefix=true]
RULE_2: /tmp/foo.txt [IsPrefix=false]
RULE_3: /tmp         [IsPrefix=true]
```
The following table demonstrates which rule will be applied for operations on a given path:
| Operation Path   | Rule Applied | Reason |
| ---------------- | ------------ | ------ |
| /tmp/foo         | `RULE_1`     | Matches prefix, more specific than `RULE_3` |
| /tmp/foo/bar     | `RULE_1`     | Matches prefix, more specific than `RULE_3` |
| /tmp/bar         | `RULE_3`     | Matches prefix |
| /tmp/foo.txt     | `RULE_2`     | Matches literal, more specific than `RULE_1` |
| /tmp/foo.txt.tmp | `RULE_1`     | Matches prefix, more specific than `RULE_3`, literal match doesn't apply |
| /foo             | N/A          | No rules match operations on this path |

> **IMPORTANT:** If a configuration contains multiple rules with duplicate configured paths, only one rule will be applied to the path. It is undefined which configured rule will be used. Administrators should take care not to define configurations that may have duplicate paths.

### Path Globs

Configured path globs represent a point in time. That is, path globs are expanded when a configuration is applied to generate the set of monitored paths. This is not a "live" representation of the filesystem. For instance, if a new file or directory is added that would match a glob after the configuration is applied, it is not immediately monitored.

Within the main Santa configuration, the `FileAccessPolicyUpdateIntervalSec` key controls how often any changes to the configuration are applied as well as re-evaluating configured path globs to match the current state of the filesystem.

### Prefix and Glob Path Evaluation

Combining path globs and the `IsPrefix` key in a configuration gives greater control over the paths that rules should match. Consider the configured path globs:
```
PG_1: /tmp/*         [IsPrefix = false]
PG_2: /tmp/*         [IsPrefix = true]
PG_3: /tmp/          [IsPrefix = true]
PG_4: /tmp/file1.txt [IsPrefix = false]
```

And a filesystem that contains:
```
/
	tmp/
		file1.txt
		file2.txt
		dir1/
			d1_f1.txt
			d1_f2.txt
```

Now, assume the configuration is applied, and moments later a new file (`/tmp/file3_new.txt`) and a new directory (`/tmp/dir2_new`) are both created:
* `PG_1` will match against the two original files within `/tmp` and the one directory `dir1` itself (but not nested contents).
* `PG_2` will match against the two original files within `/tmp` and the one directory `dir1` (as well as nested contents).
* `PG_3` will match against all original and newly created files and directories within `/tmp` (as well as nested contents).
* `PG_4` will only match `/tmp/file1.txt`.

### Case Sensitivity

All configured paths are case sensitive (i.e., paths specified in both the `Paths` and `BinaryPath` configuration keys). The case must match the case of the path as stored on the filesystem.

### Hard Links

Due to platform limitations, it is not feasible for Santa to know all links for a given path. To help mitigate bypasses to this feature, Santa will not allow hard links to be created for monitored paths. If hard links previously existed to monitored paths, Santa cannot guarantee that access to watched resources via these other links will be monitored.

## Logging

When an operation matches a defined rule, and the instigating process did not match any of the defined exceptions in the `Processes` key, the operation will be logged. Both string and protobuf logging are supported.

When the `EventLogType` configuration key is set to `syslog` or `file`, an example log message will look like:
```
action=FILE_ACCESS|policy_version=v0.1-experimental|policy_name=UserFoo|path=/Users/local/tmp/foo/text.txt|access_type=OPEN|decision=AUDIT_ONLY|pid=12|ppid=56|process=cat|processpath=/bin/cat|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id
```

When the `EventLogType` configuration key is set to `protobuf`, a log is emitted to match the `FileAccess` message in the [santa.proto](https://github.com/google/santa/blob/main/Source/common/santa.proto) schema.
