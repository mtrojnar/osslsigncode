---
name: Crash report
about: Report a segmentation fault or other crash
labels: crash
---

<!--
Thank you for your crash report.
Note: Please search to see if an issue already exists for the bug you encountered.
-->

### Segmentation Fault / Crash Details
<!--
Provide exact, reproducible steps.
Include the complete command, exactly as executed.
-->
- Signal / exit code: <!-- SIGSEGV, SIGABRT -->
- Reproducibility: <!-- always / sometimes / once -->
- Affected command or operation: <!-- e.g. `osslsigncode sign`, `osslsigncode verify` -->
- First observed version:
- Last known working version (if any):

#### Backtrace
<!--
Provide a backtrace from gdb or lldb.
Build with debug symbols if possible. Use `bt full` if possible.
Crash reports without a backtrace may be closed without investigation.
-->
- `(gdb) bt`

#### Memory / Sanitizers
<!--
Attach relevant output if available.
-->
- [ ] Valgrind
- [ ] ASan / UBSan
- [ ] Other tools

#### Crash Context
<!--
Anything that may be relevant:
- OpenSSL provider / engine in use
- PKCS#11 modules
- Custom OpenSSL configuration
- Threading or concurrency
-->

### Environment
- Operating system and version (e.g. Ubuntu 24.04):
- Architecture (x86_64, arm64, etc.):

### Versions
<!--
Please verify that the issue is reproducible with the current upstream master.
-->
- osslsigncode built from:
  - [ ] upstream master
  - [ ] upstream release (tag):
  - [ ] distribution package (name and version):
- `openssl version -a`
- `osslsigncode --version`

### Configuration / Settings
<!--
Anything that could affect signing or verification:
- Custom OpenSSL configuration
- Engine / provider settings
- Environment variables (OPENSSL_CONF, etc.)
-->

### Anything else
<!--
Links, references, related issues, workarounds or additional observations.
-->
