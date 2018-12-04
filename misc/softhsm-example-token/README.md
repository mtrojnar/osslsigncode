# softhsm-example-token

This directory contains a basic setup for testing pkcs11-support. If you get 
this to work you have a decent chance of using your real HSM or hardware token.

You need the following packages (ubuntu/debian names):

 - libengine-pkcs11-openssl
 - softhsm

Type 'make' to generate a softhsm token with a test-key on id a1b2 with PIN-code
"secret1". To use this token with osslsigncode try something like this (from this 
directory):
```
  ../../osslsigncode sign \
   -pkcs11engine /usr/lib/engines-1.1/pkcs11.so \
   -pkcs11module /usr/lib/libsofthsm2.so -key a1b2 -certs test.crt ...
```
Use 'secret1' as the password at the prompt.
