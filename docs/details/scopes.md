# Scopes

In addition to rules, Santa can allow or block based on scopes. Currently, only
a few scopes are implemented. Scopes are evaluated after rules, with block
evaluation preceding allow.

Scopes are a broader way of allowing or blocking `execve()`s.

For configuration of scopes see
[configuration.md](../deployment/configuration.md).

##### Block Scopes

Scope              | Configurable
------------------ | ------------
Blocked Path Regex | Yes
Missing __PAGEZERO | Yes

##### Allow Scopes

Scope              | Configurable
------------------ | ------------
Allowed Path Regex | Yes
Not a Mach-O       | No

As seen above, Santa will allow any non Mach-O binary under an allow scope.
However, a blocked path regex or binary SHA-256 rule can be used to block non
Mach-O `execve()`s since they are evaluated before the allow scope.

##### Regex Caveats

The paths covered by the allowed path and blocked path regex patterns are not
tracked. If an `execve()` is allowed initially, then moved into a blocked
directory, Santa has no knowledge of that move. Since `santa-driver` caches
decisions, the recently moved file will continue to be allowed to `execve()`
even though it is now within a blocked path. The cache holds "allow" decisions
until invalidated and block decisions for 500 milliseconds. Going from a blocked
path to an allowed path is not largely affected.
