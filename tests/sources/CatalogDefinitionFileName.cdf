# https://learn.microsoft.com/en-us/windows/win32/seccrypto/makecat
# makecat -v CatalogDefinitionFileName.cdf

# Define information about the entire catalog file.
[CatalogHeader]

# Name of the catalog file, including its extension.
Name=unsigned.cat

# Directory where the created unsigned.cat file will be placed.
ResultDir=..\files

# This option is not supported. Default value 1 is used.
PublicVersion=0x0000001

# Catalog version.
# If the version is set to 2, the HashAlgorithms option must contain SHA256.
CatalogVersion=2

# Name of the hashing algorithm used.
HashAlgorithms=SHA256

# Specifies whether to hash the files listed in the <HASH> option in the [CatalogFiles] section
PageHashes=true

# Type of message encoding used.
# The default EncodingType is PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0x00010001
EncodingType=0x00010001

# Specify an attribute of the catalog file.
# Set 1.3.6.1.4.1.311.12.2.1 CAT_NAMEVALUE_OBJID
# CATATTR1={type}:{oid}:{value} (optional)
# The OSAttr attribute specifies the target Windows version
CATATTR1=0x11010001:OSAttr:2:6.0

# Define each member of the catalog file.
[CatalogFiles]

<HASH>PEfile=..\files\unsigned.exe
# 0x00010000 Attribute is represented in plaintext. No conversion will be done.
<HASH>PEfileATTR1=0x11010001:File:unsigned.exe

<HASH>MSIfile=..\files\unsigned.msi
# 0x00020000 Attribute is represented in base-64 encoding.
<HASH>MSIfileATTR1=0x11020001:File:dW5zaWduZWQubXNp

<HASH>CABfile=..\files\unsigned.ex_
<HASH>CABfileATTR1=0x11010001:File:unsigned.ex_

<HASH>PS1file=..\files\unsigned.ps1
<HASH>PS1fileATTR1=0x11010001:File:unsigned.ps1

<HASH>PSC1file=..\files\unsigned.psc1
<HASH>PSC1fileATTR1=0x11010001:File:unsigned.psc1

<HASH>MOFfile=..\files\unsigned.mof
<HASH>MOFfileATTR1=0x11010001:File:unsigned.mof

<HASH>JSfile=..\files\unsigned.js
<HASH>JSfileATTR1=0x11010001:File:unsigned.js
