---
title: osslsigncode
lang: en-US
---

# NAME

osslsigncode - Authenticode signing, timestamping, extraction, attachment, removal, and verification tool

# SYNOPSIS

`osslsigncode` [`--help`] [`--version`]

`osslsigncode` `sign`
[`-certs` *file* | `-spc` *file* | `-pkcs12` *file*]
[`-key` *file-or-URI*]
[`-ac` *file*]
[`-pass` *password* | `-readpass` *file* | `-askpass`]
[`-pkcs11module` *module*] [`-pkcs11cert` *URI*]
[`-engine` *engine*] [`-provider` *provider*]
[`-login`] [`-engineCtrl` *command*[:*parameter*]]
[`-h` *digest*]
[`-n` *description*] [`-i` *URL*]
[`-jp` `low`] [`-comm`] [`-ph`]
[`-t` *URL* ... | `-ts` *URL* ...]
[`-TSA-certs` *file* `-TSA-key` *file-or-URI* [`-TSA-time` *unix-time*]]
[`-HTTPS-CAfile` *file*] [`-HTTPS-CRLfile` *file*]
[`-time` *unix-time*]
[`-addUnauthenticatedBlob` [`-blobFile` *file*]]
[`-nest`] [`-add-msi-dse`] [`-verbose`] [`-pem`]
`-in` *input* `-out` *output*

`osslsigncode` `extract-data`
[`-pem`] [`-h` *digest*] [`-ph`] [`-add-msi-dse`]
`-in` *input* `-out` *output*

`osslsigncode` `add`
[`-addUnauthenticatedBlob` [`-blobFile` *file*]]
[`-t` *URL* ... | `-ts` *URL* ...]
[`-TSA-certs` *file* `-TSA-key` *file-or-URI* [`-TSA-time` *unix-time*]]
[`-HTTPS-CAfile` *file*] [`-HTTPS-CRLfile` *file*]
[`-h` *digest*] [`-index` *n*] [`-verbose`] [`-add-msi-dse`]
`-in` *input* `-out` *output*

`osslsigncode` `attach-signature`
`-sigin` *signature*
[`-h` *digest*] [`-nest`] [`-add-msi-dse`]
`-in` *input* `-out` *output*

`osslsigncode` `extract-signature`
[`-pem`]
`-in` *input* `-out` *output*

`osslsigncode` `remove-signature`
`-in` *input* `-out` *output*

`osslsigncode` `verify`
`-in` *input*
[`-c` | `-catalog` *catalog-file*]
[`-CAfile` *file*] [`-CRLfile` *file*]
[`-HTTPS-CAfile` *file*] [`-HTTPS-CRLfile` *file*]
[`-TSA-CAfile` *file*] [`-TSA-CRLfile` *file*]
[`-p` *proxy*] [`-index` *n*]
[`-ignore-timestamp`] [`-ignore-cdp`] [`-ignore-crl`]
[`-time` *unix-time*]
[`-require-leaf-hash` *alg*:*hex*]
[`-verbose`]

# DESCRIPTION

`osslsigncode` signs and verifies Microsoft Authenticode signatures on
supported file formats.  It can also extract data for detached signing,
attach an externally produced signature, add timestamps or unauthenticated
blobs to an existing signature, and remove an embedded signature.

Supported input formats include PE files such as EXE, DLL, and SYS, CAB,
CAT, MSI, APPX, and several script file types, including `.ps1`, `.ps1xml`,
`.psc1`, `.psd1`, `.psm1`, `.cdxml`, `.mof`, and `.js`.

The program supports these common workflows:

- direct signing of an unsigned file
- detached signing via `extract-data`, `sign`, and `attach-signature`
- post-sign timestamping with `add`
- verification of embedded signatures or catalog signatures with `verify`

If no subcommand is given, `sign` is assumed.

# FORMATS

Support is not identical across all file formats.

In particular, detached-signature workflows, nested signatures, catalog-based
verification, and signature removal are format-dependent features.  A command
that is valid for one supported file type may be unsupported for another.

CAT files are a special case.  They are detached catalog containers for
hashes of other files, not ordinary embedded-signature payloads.  A CAT
file is itself a PKCS#7 structure containing authenticated entries for one
or more external files.  In practice, the catalog signs file digests
recorded in the catalog, rather than embedding a signature into each
covered file.

Because of this, CAT files behave differently from embedded-signature
formats.  They do not support `attach-signature`, `remove-signature`,
`extract-data`, or nested signatures.

MSI files are also a special case.  They support an extended signature mode
controlled by `-add-msi-dse`.  In this mode, the MSI signature covers file
metadata as well as file content.  Detached-signing workflows and any later
re-signing or nesting operations must use a mode consistent with the MSI
file's existing signature structure.

# COMMANDS

## `sign`

Create a new Authenticode signature.

This command can sign a normal unsigned file, or it can sign PKCS#7 data
previously produced by `extract-data`.

## `extract-data`

Extract the PKCS#7 content to be signed later.  This is used for detached
signing workflows.

## `add`

Add unauthenticated attributes to an existing signature, typically an
Authenticode timestamp, an RFC 3161 timestamp, or an unauthenticated blob.

With `-index`, the selected signature in a multi-signature file is updated.

## `attach-signature`

Attach a detached PKCS#7 signature to an input file.

With `-nest`, the new signature is attached as a nested signature instead of
replacing the primary one, if the file format supports nested signatures.

## `extract-signature`

Extract the embedded PKCS#7 signature from a signed file.

## `remove-signature`

Remove the embedded signature from a signed file.

## `verify`

Verify an embedded signature or a catalog signature.

Verification may include digest consistency, certificate chain validation,
certificate revocation checking, timestamp validation, and optional checking
of the signer's leaf certificate hash.

When verifying that a file is covered by a catalog, use `verify -catalog
catalog.cat -in file`.  Verifying the CAT file by itself validates the
catalog signature; verifying with `-catalog` checks whether the specified
input file is covered by that catalog.

# OPTIONS

Some options are available only in particular builds or OpenSSL versions.
In particular, `-askpass` is build-dependent, `-provider` and `-nolegacy`
require OpenSSL 3, and engine-related options depend on engine support in the
build.

## General options

`--help`  
: Show help text.  With a subcommand, show help for that subcommand.

`-v`, `--version`  
: Show version information.

`-in` *file*  
: Input file.

`-out` *file*  
: Output file.  Required for all commands except `verify`.

`-verbose`  
: Produce more detailed diagnostic output.

## Signing material

`-pkcs12` *file*  
: Read the signing certificate and private key from a PKCS#12 container.

`-certs`, `-spc` *file*  
: Read the signing certificate chain.  The historical alias `-spc` is accepted.

`-key` *file-or-URI*  
: Read the private key.  This may also be a store or PKCS#11 URI.

`-ac` *file*  
: Add extra certificates to the signature block.

`-pass` *password*  
: Password or PIN for the key, token, or PKCS#12 container.

`-readpass` *file*  
: Read the password or PIN from *file*.  Use `-` to read from standard input.

`-askpass`  
: Prompt for the password interactively.

## PKCS#11, engines, and providers

`-pkcs11module` *module*  
: Path to a PKCS#11 module.

`-pkcs11cert` *URI*  
: PKCS#11 URI identifying the certificate object.

`-provider` *provider*  
: OpenSSL 3 provider to load.  This is the preferred modern interface for
  provider-based PKCS#11 use.

`-engine`, `-pkcs11engine` *engine*  
: OpenSSL engine identifier or path to a dynamic engine module.  This
  interface is retained for compatibility with builds and deployments that
  still support engines.

`-login`  
: Force login to the token for engine-based PKCS#11 use.

`-engineCtrl` *command*[:*parameter*]  
: Pass a control command to the selected engine.

`-nolegacy`  
: On OpenSSL 3 builds, do not automatically load the legacy provider.

## Signature contents and digest control

`-h` `md5` | `sha1` | `sha2` | `sha256` | `sha384` | `sha512`  
: Select the digest algorithm.  The default is `sha256`.  `sha2` and
  `sha256` are equivalent.

`-n` *description*  
: Description of the signed content.

`-i` *URL*  
: Informational URL associated with the signed content.

`-comm`  
: Use Microsoft Commercial Code Signing purpose instead of the default
  individual purpose.

`-jp` `low`  
: Add the Java CAB permission attribute.  Only `low` is currently supported.

`-ph`  
: Generate page hashes for executable files.

`-add-msi-dse`  
: For MSI files, enable the `MsiDigitalSignatureEx` signing mode.  In this
  mode, the signature covers MSI metadata as well as file content.  The
  metadata portion includes stream names, sizes, and selected timestamps in
  the MSI structure.  This option changes the MSI signature format and should
  be used consistently in any detached-signing workflow involving
  `extract-data`, `sign`, `attach-signature`, or `add`.

  For a newly signed MSI, this mode is generally preferred because it extends
  signing coverage beyond file content alone.  For an already signed MSI,
  however, the chosen mode must match the file's existing signature
  structure.  Switching between basic MSI signing and `MsiDigitalSignatureEx`
  during re-signing or nested-signature operations can invalidate the
  existing signature.

`-pem`  
: Write PKCS#7 output in PEM format instead of DER.

## Timestamping and network options

The following timestamping modes are **mutually exclusive** within a single
`sign` or `add` invocation:

- Authenticode timestamping with `-t`
- RFC 3161 timestamping with `-ts`
- built-in RFC 3161 timestamp generation with `-TSA-certs` and `-TSA-key`

`-t` *URL*  
: Add an Authenticode timestamp from the specified URL.  May be repeated.

`-ts` *URL*  
: Add an RFC 3161 timestamp from the specified URL.  May be repeated.

`-p` *proxy*  
: Proxy used for timestamp or CRL retrieval.

`-noverifypeer`  
: Do not verify the TLS certificate of the remote timestamp service.

`-HTTPS-CAfile` *file*  
: PEM bundle used to verify HTTPS peers contacted by `osslsigncode`.

`-HTTPS-CRLfile` *file*  
: PEM CRL file used while verifying HTTPS peers.

`-TSA-certs` *file*  
: PEM certificate chain for locally generated RFC 3161 timestamps.

`-TSA-key` *file-or-URI*  
: Private key for locally generated RFC 3161 timestamps.

`-TSA-time` *unix-time*  
: Timestamp time for locally generated RFC 3161 responses.

## Nested signatures and indexed operations

`-nest`  
: Add a nested signature instead of replacing the primary signature.

`-index` *n*  
: Select a signature by index for `add` or `verify`.  Index 0 is the primary
  signature.

## Unauthenticated blob options

`-addUnauthenticatedBlob`  
: Add an unauthenticated blob to the signature.

`-blobFile` *file*  
: Read blob contents from *file*.  If omitted, a placeholder blob is created.

## Verification options

`-c`, `-catalog` *file*  
: Verify the input file against the specified catalog file.

`-CAfile` *file*  
: PEM bundle of trusted CA certificates for signer validation.

`-CRLfile` *file*  
: PEM file containing CRLs for signer validation.

`-TSA-CAfile`, `-untrusted` *file*  
: PEM bundle of trusted CA certificates for timestamp validation.

`-TSA-CRLfile`, `-CRLuntrusted` *file*  
: PEM file containing CRLs for timestamp validation.

`-time`, `-st` *unix-time*  
: Verification time.  If a valid timestamp is present and used, chain
  validation is normally performed at the timestamp time.

`-ignore-timestamp`  
: Skip verification of the timestamp signature.

`-ignore-cdp`  
: Do not fetch CRLs from CRL Distribution Points.

`-ignore-crl`  
: Disable CRL retrieval and CRL validation.

`-require-leaf-hash` *alg*:*hex*  
: Require the signer's leaf certificate to hash to the specified value.
  The hash is computed over the DER encoding of the leaf certificate.

# EXIT STATUS

`0`  
: Success.

non-zero  
: Failure.

# DIAGNOSTICS

Common causes of failure include:

missing CA trust bundle  
: On Unix-like systems, `verify` expects a readable CA bundle, either from
  `-CAfile` or from a detected system default.

detached-signing mismatch  
: `extract-data`, `sign`, and `attach-signature` must use compatible
  digest-affecting options such as `-h`, and where relevant `-ph` and
  `-add-msi-dse`.

unsupported format feature  
: Some file formats do not support every subcommand or every signature mode.

missing TSA trust chain  
: Timestamp verification may fail unless the appropriate TSA trust anchors
  are supplied with `-TSA-CAfile`, and where needed `-TSA-CRLfile`.

conflicting timestamp modes  
: `-t`, `-ts`, and built-in TSA signing cannot be combined in one command.

MSI signature mode mismatch  
: Re-signing or nesting an MSI signature must be consistent with whether the
  file already uses `MsiDigitalSignatureEx`.  Mixing modes may invalidate the
  existing signature.

# ENVIRONMENT

`HTTP_PROXY`, `http_proxy`  
: Default proxy for HTTP access if `-p` is not given.

`HTTPS_PROXY`, `https_proxy`  
: Default proxy for HTTPS access if `-p` is not given.

`OPENSSL_ENGINES`  
: May help OpenSSL find engine modules.

# FILES

On Unix-like systems, `osslsigncode` tries common CA bundle locations for
its default `-CAfile`, including:

- `/etc/ssl/certs/ca-certificates.crt`
- `/etc/pki/tls/certs/ca-bundle.crt`
- `/usr/share/ssl/certs/ca-bundle.crt`
- `/usr/local/share/certs/ca-root-nss.crt`
- `/etc/ssl/cert.pem`

If no readable CA bundle is available, `verify` may require an explicit
`-CAfile`.

# NOTES

Use `extract-data` when you need to create a new detached signature object.
Use `extract-signature` when you need to copy an existing embedded PKCS#7
signature out of a file.

For safer secret handling, prefer `-readpass` or `-askpass` over `-pass`.

Data added with `-addUnauthenticatedBlob` is not protected by the signature
and must not be treated as trusted.

For new MSI signatures, `-add-msi-dse` is generally preferred because it
extends signing coverage to MSI metadata as well as file content.  However,
it is format-affecting rather than cosmetic, so existing signed MSI files
should be re-signed only in a mode consistent with their current signature
structure.

Output files are not overwritten.

# EXAMPLES

## Sign and verify a file

```sh
osslsigncode sign \
  -pkcs12 signer.p12 \
  -readpass p12-pass.txt \
  -n "Example Application" \
  -i "https://example.com/" \
  -ts "https://tsa.example.net/" \
  -in app.exe \
  -out app-signed.exe

osslsigncode verify \
  -CAfile ca-bundle.pem \
  -TSA-CAfile tsa-ca-bundle.pem \
  -in app-signed.exe
```

## Detached signing workflow

```sh
osslsigncode extract-data \
  -h sha384 \
  -ph \
  -in app.exe \
  -out app-data.der

osslsigncode sign \
  -pkcs12 signer.p12 \
  -readpass p12-pass.txt \
  -h sha384 \
  -in app-data.der \
  -out app-sig.der

osslsigncode attach-signature \
  -h sha384 \
  -sigin app-sig.der \
  -in app.exe \
  -out app-signed.exe

osslsigncode verify \
  -CAfile ca-bundle.pem \
  -in app-signed.exe
```

## Sign a new MSI with extended MSI metadata coverage

```sh
osslsigncode sign \
  -pkcs12 signer.p12 \
  -readpass p12-pass.txt \
  -add-msi-dse \
  -in installer.msi \
  -out installer-signed.msi
```

## Use a PKCS#11 provider

```sh
osslsigncode sign \
  -provider /path/to/pkcs11prov.so \
  -pkcs11module /path/to/opensc-pkcs11.so \
  -pkcs11cert 'pkcs11:token=my-token;object=cert' \
  -key 'pkcs11:token=my-token;object=key' \
  -readpass pin.txt \
  -in app.exe \
  -out app-signed.exe
```

## Add a timestamp to an already signed file

```sh
osslsigncode add \
  -ts "https://tsa.example.net/" \
  -in app-signed.exe \
  -out app-signed-ts.exe
```

## Verify that a file is covered by a catalog

```sh
osslsigncode verify \
  -catalog drivers.cat \
  -CAfile ca-bundle.pem \
  -CRLfile ca-crl.pem \
  -in driver.sys
```

# REPORTING BUGS

Report bugs and suspected issues via the project issue tracker:

<https://github.com/mtrojnar/osslsigncode/issues>

# AUTHORS

Originally written by Per Allansson.

Maintained and extended by Michał Trojnara.

Major contributions by Małgorzata Olszówka.

Additional contributions by other project contributors.

# SEE ALSO

**OpenSSL** Library

<https://openssl-library.org/>

