# Changelog

## [3.0.0] - 2024-05-25 [Draft] [Unreleased]

_Enhance script robustness, simplicity, portability, and performance._

The leading goal is to make the script more *robust* and *maintainable*,
while enhancing its *simplicity*, *portability* and *performance*. Commits
have been combined into a cohesive whole for greater clarity. [TigerStyle]
was followed when possible.

## Changes

There are extensive changes, including but not limited to the following:

#### *Robustness*

- Fix all `shellcheck` warnings, errors and issues (`45` warnings, `53` info).
- Fix potentially removing root directory on empty values.
- Add better checks, constraints, redirections and exit codes.
- Add logic to handle Shodan membership warning instead of returning errors.
- Use `set -Cefu` to enforce error exits, prevent var misuse
  and ensure safer file redirections.[^cefu]
- Add fallbacks and support environmental variables.
- Use unified curl connections...
- Upgrade most `curl` insecure connections to not use `-k`.

#### *Simplicity*

- Reduce codebase by around a half of its original size:  
  *≈ **51.72%** code reduction*
  *(`36663` -> `17754` bytes, `1033` -> `946` lines).*
- Remove redundancy with functions, loops, and variables.
- Use composability over hardcoded and heavily coupled code.
- Use lowercase for variable names, as it's idiomatic to reserve uppercase
  for environmental variables.
- Removed comments in favor of concise code and descriptive naming.

#### *Portability*

- Enhance script portability to run with other POSIX shells, supporting:  
  *`bash`, `dash`, `ksh93`, `mksh`, `oksh`, `osh`, `posh`, `yash`, `zsh`.*
- Use `/bin/sh` with standard idioms, following POSIX spec closely.
- Support and test different platforms `Linux`, `macOS`, `FreeBSD`.
- Migrate `grep -P` PCRE regex to POSIX-compatible regular expressions.

#### *Performance*

- Reduce runtime overhead performance ≈ `55 ms`, from `205.9 ms`
  to `150.6 ms`.[^hyperfine]
- Reduce the number of syscalls, from `5279` to `4530` total.[^dtrace]
- Use the system default nameserver instead of `8.8.8.8`.

#### *Other Features*

- Add new logo.
- Add `XDG_DATA_HOME` support loading fallbacks  
  (e.g. `API.conf`, `XDG_DATA_HOME/behindTheCDN/API.conf`,
  `$HOME/.local/share/behindTheCDN/API.conf`).
- Display colors only in terminal outputs, not in pipes or file writes.
- Check dependencies availability in current environment.
- Add `-n` to disable terminal colors.
- Deprecated `-i` in favor of `-a` and `-hmsc`
- Add manpage using [`mdoc`][]

---

The new version should have equivalent functionality.  
Further testing is recommended.

[`mdoc`]: https://manpages.bsd.lv/mdoc.html

[TigerStyle]: https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md

[^cefu]: *See*: [ExplainShell: set -Cefu](https://explainshell.com/explain?cmd=set+-Cefu)
[^dtrace]: *cfr.* Counted with `dtrace` under _Kali Linux 2024.1_, with `-c`.
[^hyperfine]: *cfr.* Benchmarked with `hyperfine` on `-d 127.0.0.1`.
