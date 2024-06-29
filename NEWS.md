# osslsigncode change log

### 2.9 (2024.06.29)

- added a 64 bit long pseudo-random NONCE in the TSA request
- missing NID_pkcs9_signingTime is no longer an error
- added support for PEM-encoded CRLs
- fixed the APPX central directory sorting order
- added a special "-" file name to read the passphrase from stdin
  (by Steve McIntyre)
- used native HTTP client with OpenSSL 3.x, removing libcurl dependency
- added '-login' option to force a login to PKCS11 engines
  (by Brad Hughes)
- added the "-ignore-crl" option to disable fetching and verifying
  CRL Distribution Points
- changed error output to stderr instead of stdout
- various testing framework improvements
- various memory corruption fixes

### 2.8 (2024.03.03)

- Microsoft PowerShell signing sponsored by Cisco Systems, Inc.
- fixed setting unauthenticated attributes (Countersignature, Unauthenticated
  Data Blob) in a nested signature
- added the "-index" option to verify a specific signature or modify its
  unauthenticated attributes
- added CAT file verification
- added listing the contents of a CAT file with the "-verbose" option
- added the new "extract-data" command to extract a PKCS#7 data content to be
  signed with "sign" and attached with "attach-signature"
- added PKCS9_SEQUENCE_NUMBER authenticated attribute support
- added the "-ignore-cdp" option to disable CRL Distribution Points (CDP)
  online verification
- unsuccessful CRL retrieval and verification changed into a critical error
- the "-p" option modified to also use to configured proxy to connect CRL
  Distribution Points
- added implicit allowlisting of the Microsoft Root Authority serial number
  00C1008B3C3C8811D13EF663ECDF40
- added listing of certificate chain retrieved from the signature in case of
  verification failure

### 2.7 (2023.09.19)

- fixed signing CAB files (by Michael Brown)
- fixed handling of unsupported commands (by Maxim Bagryantsev)
- fixed writing DIFAT sectors
- added APPX support (by Maciej Panek and Małgorzata Olszówka)
- added a built-in TSA response generation (-TSA-certs, -TSA-key
  and -TSA-time options)

### 2.6 (2023.05.29)

- modular architecture implemented to simplify adding file formats
- added verification of CRLs specified in the signing certificate
- added MSI DIFAT sectors support (by Max Bagryantsev)
- added legacy provider support for OpenSSL 3.0.0 and later
- fixed numerous bugs

### 2.5 (2022.08.12)

- fixed the Unix executable install path
- fixed the hardcoded "pkcs11" engine id
- fixed building with MinGW
- fixed testing with the python3 distributed with Ubuntu 18.04

### 2.4 (2022.08.02)

- migrated the build system from GNU Autoconf to CMake
- added the "-h" option to set the cryptographic hash function
  for the "attach -signature" and "add" commands
- set the default hash function to "sha256"
- added the "attach-signature" option to compute and compare the
  leaf certificate hash for the "add" command
- renamed the "-st" option "-time" (the old name is accepted for
  compatibility)
- updated the "-time" option to also set explicit verification time
- added the "-ignore-timestamp" option to disable timestamp server
  signature verification
- removed the "-timestamp-expiration" option
- fixed several bugs
- updated the included documentation
- enabled additional compiler/linker hardening options
- added CI based on GitHub Actions

### 2.3 (2022.03.06)

**CRITICAL SECURITY VULNERABILITIES**

This release fixes several critical memory corruption vulnerabilities.
A malicious attacker could create a file, which, when processed with
osslsigncode, triggers arbitrary code execution.  Any previous version
of osslsigncode should be immediately upgraded if the tool is used for
processing of untrusted files.

- fixed several memory safety issues
- fixed non-interactive PVK (MSBLOB) key decryption
- added a bash completion script
- added CA bundle path auto-detection

### 2.2 (2021.08.15)

- CAT files support (thanks to James McKenzie)
- MSI support rewritten without libgsf dependency, which allows
  for handling of all the needed MSI metadata, such as dates
- "-untrusted" option renamed to "-TSA-CAfile"
- "-CRLuntrusted" option renamed to "-TSA-CRLfile"
- numerous bug fixes and improvements

### 2.1 (2020-10-11)

- certificate chain verification support
- timestamp verification support
- CRL verification support ("-CRLfile" option)
- improved CAB signature support
- nested signatures support
- user-specified signing time ("-st" option) by vszakats
- added more tests
- fixed numerous bugs
- dropped OpenSSL 1.1.0 support

### 2.0 (2018-12-04)

- orphaned project adopted by Michał Trojnara
- ported to OpenSSL 1.1.x
- ported to SoftHSM2
- add support for pkcs11-based hardware tokens
  (Patch from Leif Johansson)
- improved error reporting of timestamping errors
  (Patch from Carlo Teubner)

### 1.7.1 (2014-07-11)

- MSI: added -add-msi-dse option
  (Patch from Mikkel Krautz)
- MSI: fix build when GSF_CAN_READ_MSI_METADATA defined
  (Patch from Mikkel Krautz)

### 1.7 (2014-07-10)

- add support for nested signatures
  (Patch from Mikkel Krautz)
- fix compilation problem with OpenSSL < 1.0.0
- added OpenSSL linkage exception to license

### 1.6 (2014-01-21)

- add support for reading password from file
- add support for asking for password (on systems that
  provide support for it)
- add support for compiling and running on Windows
  (Patch from Heiko Hund)
- fix compilation without curl
  (Fix from Heiko Hund)
- added support for giving multiple timestamp servers
  as arguments (first one that succeeds will be used)
- signatures on hierarchical MSI files were broken
  (Fix from Mikkel Krautz)
- MSI: Add support for MsiDigitalSignatureEx signature
  (Patch from Mikkel Krautz)
- add support for adding additional/cross certificates
  through -ac option
  (Thanks to Lars Munch for idea + testing)
- MSI: Add support for signature extract/remove/verify
  (Patches from Mikkel Krautz)
- PE/MSI: Implement -require-leaf-hash for verify.
  (Patch from Mikkel Krautz)

### 1.5.2 (2013-03-13)

- added support for signing with SHA-384 and SHA-512
- added support for page hashing (-ph option)

### 1.5.1 (2013-03-12)

- forgot to bump version number...

### 1.5 (2013-03-12)

- added support for signing MSI files (patch from Marc-André Lureau)
- calculate correct PE checksum instead of setting it to 0
  (patch from Roland Schwingel)
- added support for RFC3161 timestamping (-ts option)
- added support for extracting/removing/verifying signature on PE files
- fixed problem with not being able to decode timestamps with no newlines
- added stricter checks for PE file validity
- added support for reading keys from PVK files (requires OpenSSL 1.0.0 or later)
- added support for reading certificates from PEM files
- renamed program option: -spc to -certs (old option name still valid)

### 1.4 (2011-08-12)

- improved build system (patch from Alon Bar-Lev)
- support reading cert+key from PKCS12 file (patch from Alon Bar-Lev)
- support reading key from PEM file
- added support for sha1/sha256 - default hash is now sha1
- added flag for commercial signing (default is individual)

### 1.3.1 (2009-08-07)

- support signing of 64-bit executables (fix  from Paul Kendall)

### 1.3 (2008-01-31)

- fixed padding problem (fix from Ryan Rubley)
- allow signing of already signed files (fix from Ryan Rubley)
- added Ryan Rubley's PVK-to-DER guide into the README

### 1.2 (2005-01-21)

- autoconf:ed (Thanks to Roy Keene)
- added documentation
- don't override PKCS7_get_signed_attribute, it wasn't
  actually needed, it was me being confused.
- compiles without curl, which means no timestamping
- version number output

### 1.1 (2005-01-19)

- Initial release
