# Web-server lineage on Windows and macOS (T1190, #376)

A web or application server that starts a command interpreter is the process-lineage shape of
an exploited public-facing application: a webshell, a deserialization or template-injection
bug, a command-injection endpoint. Three rules name it, one per platform family:

| Platform | Rule | Parent | Child | Technique |
| --- | --- | --- | --- | --- |
| Linux | `RuleState::check_web_server_spawns_shell` (`crates/rules`) | `nginx`, `apache2`, `httpd`, `php-fpm*`, `mysqld`, `mariadbd`, `postgres` | `sh`, `bash`, `dash`, `zsh`, `ash` | **T1059** (the rule predates this pack and keeps its tag) |
| Windows | `rules/sigma/windows/iis_worker_spawned_interpreter.yml` | `w3wp.exe` | `cmd`, `powershell`, `pwsh`, `wscript`, `cscript` | T1190 |
| Windows | `rules/sigma/windows/web_server_spawned_interpreter.yml` | `httpd.exe`, `nginx.exe`, `php-cgi.exe`, `tomcat8`..`tomcat11.exe` | the same five | T1190 |
| macOS | `rules/sigma/macos/web_server_spawned_shell.yml` | `httpd`, `nginx`, `php-fpm` | `sh`, `bash`, `zsh`, `dash` | T1190 |

The two Sigma rules are Medium. A match is a lineage fact: it does not say the pair was
exploited, and the rule's `falsepositives` names the expected cases (a CGI script or a
deployment hook that calls a shell on purpose, mostly on development and staging hosts; XAMPP
and WAMP run CGI through `cmd.exe`).

## What the Sigma rules need

`ParentImage` matches only when the sensor fills the parent's image path
(`ExecEvent::parent_image_path`); without it the rule cannot match and does not guess. Checked
in the code, not on a host: the macOS Endpoint Security sensor sets it from the exec event's
parent path (`crates/sensors/macos/endpoint-security/src/normalize.rs`), the Windows ETW path
is the one the IIS rule already relies on. **No lab run is claimed** for either.

The parent and the child are matched by `endswith` on a path separator (`\httpd.exe`, `/httpd`),
so `myhttpd.exe` and `nginx-helper` do not match. Tests cover every listed parent against every
listed child, those lookalikes, and an exec with no lineage.

## Stated gaps

- **`java` as the parent.** A Tomcat started from a console script runs as `java` / `java.exe`,
  too common a parent to list. The `tomcat8.exe`..`tomcat11.exe` names are the Windows service
  wrapper only. Tomcat on macOS is therefore not covered.
- **Other servers**: Caddy, lighttpd, `uwsgi`/`gunicorn` (application servers run as
  `python`), Node and Ruby servers. Not listed: their process name is the language runtime.
- **A different interpreter**: a server that starts `python`, `perl` or `curl` directly
  (a webshell that runs those without a shell) is not in these rules.
- **Each host loads only the rules its platform runs** (`SigmaEngine::load_dir_for`, #980: Linux
  `linux/`, Windows `windows/`, macOS `macos/` and `linux/`). The macOS rule therefore runs on macOS
  hosts only, and a Linux host raises one finding for a web server starting a shell (the T1059 rule
  of the rule engine), not two. Until #980 the agent loaded the whole tree and the
  macOS rule also fired on Linux beside the T1059 rule.
- **The Linux rule keeps T1059.** Re-tagging it would change the technique of existing alerts
  and the tests that pin it; the Sigma siblings carry T1190, and the generated coverage matrix
  lists both.
