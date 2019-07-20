# Scopes

In addition to rules, Santa can whitelist or blacklist based on scopes. Currently, only a few scopes are implemented. They fall into one of two categories: a whitelist scope or blacklist scope. Scopes are evaluated after rules, with blacklist evaluation preceding whitelist.

Scopes are a broader way of whitelisting or blacklisting `execve()`s.

For configuration of scopes see [configuration.md](../deployment/configuration.md).

##### Blacklist Scopes

| Scope                | Configurable |
| -------------------- | ------------ |
| Blacklist Path Regex | Yes          |
| Missing __PAGEZERO   | Yes          |

##### Whitelist Scopes

| Scope                | Configurable |
| -------------------- | ------------ |
| Whitelist Path Regex | Yes          |
| Not a Mach-O         | No           |

As seen above, Santa will whitelist any non Mach-O binary under a whitelist scope. However, a blacklist regex or binary SHA-256 rule can be used to block non Mach-O `execve()`s since they are evaluated before the whitelist scopes.

##### Regex Caveats

The paths covered by the whitelist and blacklist regex patterns are not tracked. If an `execve()` is allowed initially, then moved into a blacklist directory, Santa has no knowledge of that move. Since santa-driver caches decisions, the recently moved file will continue to be allowed to `execve()` even though it is now within a blacklisted regex path. The cache holds "allow" decisions until invalidated and "deny" decisions for 500 milliseconds. Going from a blacklist path to a whitelist path is not largely affected.