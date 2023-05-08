# make test
# ctest -C Release

########## Configure ##########

option(STOP_SERVER "Stop HTTP server after tests" ON)

include(FindPython3)

set(TEST_DIR "${PROJECT_BINARY_DIR}/Testing")
file(COPY
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/files"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/conf"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/client_http.py"
    DESTINATION "${TEST_DIR}/")

file(MAKE_DIRECTORY "${TEST_DIR}/logs")

set(FILES "${TEST_DIR}/files")
set(CERTS "${TEST_DIR}/certs")
set(CONF "${TEST_DIR}/conf")
set(LOGS "${TEST_DIR}/logs")
set(CLIENT_HTTP "${TEST_DIR}/client_http.py")

if(UNIX)
    file(COPY
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/server_http.py"
        DESTINATION "${TEST_DIR}/")
    set(SERVER_HTTP "${TEST_DIR}/server_http.py")
else(UNIX)
    file(COPY
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/server_http.pyw"
        DESTINATION "${TEST_DIR}/")
    set(SERVER_HTTP "${TEST_DIR}/server_http.pyw")
endif(UNIX)

file(COPY
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/ca-bundle.crt"
    DESTINATION "${CONF}")

if(WIN32 OR APPLE)
    if(WIN32)
        message(STATUS "Use pythonw to start HTTP server: \"pythonw.exe Testing\\server_http.pyw\"")
    else(WIN32)
        message(STATUS "Use python3 to start HTTP server: \"python3 Testing/server_http.py --port 19254\"")
    endif(WIN32)
    set(default_certs 1)
else(WIN32 OR APPLE)
    if(Python3_FOUND)
        if(EXISTS ${LOGS}/port.log)
            # Stop HTTP server if running
            message(STATUS "Try to kill HTTP server")
            execute_process(
                COMMAND ${Python3_EXECUTABLE} "${CLIENT_HTTP}"
                WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
                OUTPUT_VARIABLE client_output
                RESULT_VARIABLE client_result)
            if(NOT client_result)
                # Successfully closed
                message(STATUS "${client_output}")
            endif(NOT client_result)
        endif(EXISTS ${LOGS}/port.log)

        # Start Time Stamping Authority and CRL distribution point HTTP server
        execute_process(
            COMMAND ${Python3_EXECUTABLE} "${SERVER_HTTP}"
            WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
            OUTPUT_FILE ${LOGS}/server.log
            ERROR_FILE ${LOGS}/server.log
            RESULT_VARIABLE server_error)
        if(server_error)
            message(STATUS "HTTP server failed: ${server_error}")
        else(server_error)
            # Check if file exists and is no-empty
            while(NOT EXISTS ${LOGS}/port.log)
                execute_process(COMMAND sleep 1)
            endwhile(NOT EXISTS ${LOGS}/port.log)
            file(READ ${LOGS}/port.log PORT)
            while(NOT PORT)
                execute_process(COMMAND sleep 1)
                file(READ ${LOGS}/port.log PORT)
            endwhile(NOT PORT)
            file(STRINGS ${LOGS}/server.log server_log)
            message(STATUS "${server_log}")

            # Generate new cTest certificates
            if(NOT SED_EXECUTABLE)
                find_program(SED_EXECUTABLE sed)
                mark_as_advanced(SED_EXECUTABLE)
            endif(NOT SED_EXECUTABLE)
            execute_process(
                COMMAND ${SED_EXECUTABLE}
                    -i.bak s/:19254/:${PORT}/ "${CONF}/openssl_intermediate_crldp.cnf"
                COMMAND ${SED_EXECUTABLE}
                    -i.bak s/:19254/:${PORT}/ "${CONF}/openssl_tsa_root.cnf")
            execute_process(
                COMMAND "${CONF}/makecerts.sh"
                WORKING_DIRECTORY ${CONF}
                OUTPUT_VARIABLE makecerts_output
                RESULT_VARIABLE default_certs)
            message(STATUS "${makecerts_output}")
        endif(server_error)
    endif(Python3_FOUND)

endif(WIN32 OR APPLE)

# Copy the set of default certificates
if(default_certs)
    message(STATUS "Default certificates used by cTest")
    set(PORT 19254)
    file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs"
        DESTINATION "${TEST_DIR}")
endif(default_certs)

# Compute a SHA256 hash of the leaf certificate (in DER form)
execute_process(
    COMMAND ${CMAKE_COMMAND} -E sha256sum "${CERTS}/cert.der"
    OUTPUT_VARIABLE sha256sum)
string(SUBSTRING ${sha256sum} 0 64 leafhash)


########## Testing ##########

enable_testing()

set(extensions_4 "exe" "ex_" "msi" "cat")
set(extensions_3 "exe" "ex_" "msi")

# Test 1
# Print osslsigncode version
add_test(NAME version
    COMMAND osslsigncode --version)

### Sign ###

# Tests 2-5
# Sign with PKCS#12 container with legacy RC2-40-CBC private key and certificate encryption algorithm
foreach(ext ${extensions_4})
    add_test(
        NAME legacy_${ext}
        COMMAND osslsigncode "sign"
        "-pkcs12" "${CERTS}/legacy.p12"
        "-readpass" "${CERTS}/password.txt"
        "-ac" "${CERTS}/crosscert.pem"
        "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
        "-add-msi-dse"
        "-comm"
        "-ph"
        "-jp" "low"
        "-h" "sha512" "-i" "https://www.osslsigncode.com/"
        "-n" "osslsigncode"
        "-in" "${FILES}/unsigned.${ext}"
        "-out" "${FILES}/legacy.${ext}")
endforeach(ext ${extensions_4})

# Tests 6-9
# Sign with PKCS#12 container with legacy RC2-40-CBC private key and certificate encryption algorithm
# Disable legacy mode and don't automatically load the legacy provider
# Option "-nolegacy" requires OpenSSL 3.0.0 or later
# This tests are expected to fail
if(OPENSSL_VERSION VERSION_GREATER_EQUAL 3.0.0)
    foreach(ext ${extensions_4})
        add_test(
            NAME nolegacy_${ext}
            COMMAND osslsigncode "sign"
            "-pkcs12" "${CERTS}/legacy.p12"
            "-readpass" "${CERTS}/password.txt"
            "-nolegacy" # Disable legacy mode
            "-ac" "${CERTS}/crosscert.pem"
            "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
            "-add-msi-dse"
            "-comm"
            "-ph"
            "-jp" "low"
            "-h" "sha512" "-i" "https://www.osslsigncode.com/"
            "-n" "osslsigncode"
            "-in" "${FILES}/unsigned.${ext}"
            "-out" "${FILES}/nolegacy.${ext}")
        set_tests_properties(
            nolegacy_${ext}
            PROPERTIES
            WILL_FAIL TRUE)
    endforeach(ext ${extensions_4})
endif(OPENSSL_VERSION VERSION_GREATER_EQUAL 3.0.0)

# Tests 10-13
# Sign with PKCS#12 container with AES-256-CBC private key and certificate encryption algorithm
foreach(ext ${extensions_4})
    add_test(
        NAME signed_${ext}
        COMMAND osslsigncode "sign"
        "-pkcs12" "${CERTS}/cert.p12"
        "-readpass" "${CERTS}/password.txt"
        "-ac" "${CERTS}/crosscert.pem"
        "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
        "-add-msi-dse"
        "-comm"
        "-ph"
        "-jp" "low"
        "-h" "sha512" "-i" "https://www.osslsigncode.com/"
        "-n" "osslsigncode"
        "-in" "${FILES}/unsigned.${ext}"
        "-out" "${FILES}/signed.${ext}")
endforeach(ext ${extensions_4})

# Tests 14-17
# Sign with revoked certificate
foreach(ext ${extensions_4})
    add_test(
        NAME revoked_${ext}
        COMMAND osslsigncode "sign"
        "-certs" "${CERTS}/revoked.pem"
        "-key" "${CERTS}/keyp.pem"
        "-readpass" "${CERTS}/password.txt"
        "-ac" "${CERTS}/crosscert.pem"
        "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
        "-add-msi-dse"
        "-comm"
        "-ph"
        "-jp" "low"
        "-h" "sha512" "-i" "https://www.osslsigncode.com/"
        "-n" "osslsigncode"
        "-in" "${FILES}/unsigned.${ext}"
        "-out" "${FILES}/revoked.${ext}")
endforeach(ext ${extensions_4})

# Tests 18-20
# Remove signature
# Unsupported command for CAT files
foreach(ext ${extensions_3})
    add_test(
        NAME removed_${ext}
        COMMAND osslsigncode "remove-signature"
        "-in" "${FILES}/signed.${ext}"
        "-out" "${FILES}/removed.${ext}")
    set_tests_properties(
        removed_${ext}
        PROPERTIES
        DEPENDS "signed_${ext}"
        REQUIRED_FILES "${FILES}/signed.${ext}")
endforeach(ext ${extensions_3})

# Tests 21-24
# Extract PKCS#7 signature in PEM format
foreach(ext ${extensions_4})
    add_test(
        NAME extract_pem_${ext}
        COMMAND osslsigncode "extract-signature"
        "-pem" # PEM format
        "-in" "${FILES}/signed.${ext}"
        "-out" "${FILES}/${ext}.pem")
    set_tests_properties(
        extract_pem_${ext}
        PROPERTIES
        DEPENDS "signed_${ext}"
        REQUIRED_FILES "${FILES}/signed.${ext}")
endforeach(ext ${extensions_4})

# Tests 25-28
# Extract PKCS#7 signature in default DER format
foreach(ext ${extensions_4})
    add_test(
        NAME extract_der_${ext}
        COMMAND osslsigncode "extract-signature"
        "-in" "${FILES}/signed.${ext}"
        "-out" "${FILES}/${ext}.der")
    set_tests_properties(
        extract_der_${ext}
        PROPERTIES
        DEPENDS "signed_${ext}"
        REQUIRED_FILES "${FILES}/signed.${ext}")
endforeach(ext ${extensions_4})

# Tests 29-34
# Attach signature in PEM or DER format
# Unsupported command for CAT files
set(formats "pem" "der")
foreach(ext ${extensions_3})
    foreach(format ${formats})
        add_test(
            NAME attached_${format}_${ext}
            COMMAND osslsigncode "attach-signature"
            # sign options
            "-time" "1567296000" # Signing and signature verification time: Sep  1 00:00:00 2019 GMT
            "-require-leaf-hash" "SHA256:${leafhash}"
            "-add-msi-dse"
            "-h" "sha512"
            "-nest"
            "-sigin" "${FILES}/${ext}.${format}"
            "-in" "${FILES}/signed.${ext}"
            "-out" "${FILES}/attached_${format}.${ext}"
            # verify options
            "-CAfile" "${CERTS}/CACert.pem"
            "-CRLfile" "${CERTS}/CACertCRL.pem")
        set_tests_properties(
            attached_${format}_${ext}
            PROPERTIES
            DEPENDS "signed_${ext}:extract_${format}_${ext}"
            REQUIRED_FILES "${FILES}/signed.${ext}"
            REQUIRED_FILES "${FILES}/${ext}.${format}")
    endforeach(format ${formats})
endforeach(ext ${extensions_3})

# Tests 35-38
# Add an unauthenticated blob to a previously-signed file
foreach(ext ${extensions_4})
    add_test(
        NAME added_${ext}
        COMMAND osslsigncode "add"
        "-addUnauthenticatedBlob"
        "-add-msi-dse" "-h" "sha512"
        "-in" "${FILES}/signed.${ext}"
        "-out" "${FILES}/added.${ext}")
    set_tests_properties(
        added_${ext}
        PROPERTIES
        DEPENDS "signed_${ext}"
        REQUIRED_FILES "${FILES}/signed.${ext}")
endforeach(ext ${extensions_4})

# Tests 39-42
# Add the new nested signature instead of replacing the first one
foreach(ext ${extensions_4})
    add_test(
        NAME nested_${ext}
        COMMAND osslsigncode "sign"
        "-nest"
        "-certs" "${CERTS}/cert.pem"
        "-key" "${CERTS}/key.der"
        "-pass" "passme"
        "-ac" "${CERTS}/crosscert.pem"
        "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
        "-add-msi-dse"
        "-comm"
        "-ph"
        "-jp" "low"
        "-h" "sha512"
        "-i" "https://www.osslsigncode.com/"
        "-n" "osslsigncode"
        "-in" "${FILES}/signed.${ext}"
        "-out" "${FILES}/nested.${ext}")
    set_tests_properties(
        nested_${ext}
        PROPERTIES
        DEPENDS "signed_${ext}"
        REQUIRED_FILES "${FILES}/signed.${ext}")
endforeach(ext ${extensions_4})


### Verify signature ###

# Tests 43-45
# Verify PE/MSI/CAB files signed in the catalog file
foreach(ext ${extensions_3})
    add_test(
        NAME verify_catalog_${ext}
        COMMAND osslsigncode "verify"
        "-catalog" "${FILES}/signed.cat" # catalog file
        "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
        "-require-leaf-hash" "SHA256:${leafhash}"
        "-CAfile" "${CERTS}/CACert.pem"
        "-CRLfile" "${CERTS}/CACertCRL.pem"
        "-in" "${FILES}/unsigned.${ext}")
    set_tests_properties(
        verify_catalog_${ext}
        PROPERTIES
        DEPENDS "signed_${ext}"
        REQUIRED_FILES "${FILES}/signed.cat"
        REQUIRED_FILES "${FILES}/unsigned.${ext}")
endforeach(ext ${extensions_3})

# Tests 46-69
# Verify signature
set(files "legacy" "signed" "nested" "added" "removed" "revoked" "attached_pem" "attached_der")
foreach(file ${files})
    foreach(ext ${extensions_3})
        add_test(
            NAME verify_${file}_${ext}
            COMMAND osslsigncode "verify"
            "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
            "-CAfile" "${CERTS}/CACert.pem"
            "-CRLfile" "${CERTS}/CACertCRL.pem"
            "-in" "${FILES}/${file}.${ext}")
        set_tests_properties(
            verify_${file}_${ext}
            PROPERTIES
            DEPENDS "${file}_${ext}"
            REQUIRED_FILES "${FILES}/${file}.${ext}")
    endforeach(ext ${extensions_3})
endforeach(file ${files})

# "Removed" and "revoked" tests are expected to fail
set(files "removed" "revoked")
foreach(file ${files})
    foreach(ext ${extensions_3})
        set_tests_properties(
            verify_${file}_${ext}
            PROPERTIES
            WILL_FAIL TRUE)
    endforeach(ext ${extensions_3})
endforeach(file ${files})

if(Python3_FOUND OR server_error)

### Sign with Time-Stamp Authority ###

    # Tests 70-89
    # Sign with the RFC3161 Time-Stamp Authority
    # Use "cert" "expired" "revoked" without X509v3 CRL Distribution Points extension
    # and "cert_crldp" "revoked_crldp" contain X509v3 CRL Distribution Points extension
    set(pem_certs "cert" "expired" "revoked" "cert_crldp" "revoked_crldp")
    foreach(ext ${extensions_4})
        foreach(cert ${pem_certs})
            add_test(
                NAME sign_ts_${cert}_${ext}
                COMMAND osslsigncode "sign"
                "-certs" "${CERTS}/${cert}.pem"
                "-key" "${CERTS}/key.pem"
                "-ac" "${CERTS}/crosscert.pem"
                "-comm"
                "-ph"
                "-jp" "low"
                "-h" "sha384"
                "-i" "https://www.osslsigncode.com/"
                "-n" "osslsigncode"
                "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
                "-ts" "http://127.0.0.1:${PORT}"
                "-in" "${FILES}/unsigned.${ext}"
                "-out" "${FILES}/ts_${cert}.${ext}")
            set_tests_properties(
                sign_ts_${cert}_${ext}
                PROPERTIES
                REQUIRED_FILES "${LOGS}/port.log")
        endforeach(cert ${pem_certs})
    endforeach(ext ${extensions_4})


### Verify Time-Stamp Authority ###

    # Tests 90-92
    # Signature verification time: Sep  1 00:00:00 2019 GMT
    foreach(ext ${extensions_3})
        add_test(
            NAME verify_ts_cert_${ext}
            COMMAND osslsigncode "verify"
            "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
            "-CAfile" "${CERTS}/CACert.pem"
            "-TSA-CAfile" "${CERTS}/TSACA.pem"
            "-in" "${FILES}/ts_cert.${ext}")
        set_tests_properties(
            verify_ts_cert_${ext}
            PROPERTIES
            DEPENDS "sign_ts_cert_${ext}"
            REQUIRED_FILES "${FILES}/ts_cert.${ext}"
            REQUIRED_FILES "${LOGS}/port.log")
    endforeach(ext ${extensions_3})

    # Tests 93-95
    # Signature verification time: Jan  1 00:00:00 2035 GMT
    foreach(ext ${extensions_3})
        add_test(
            NAME verify_ts_future_${ext}
            COMMAND osslsigncode "verify"
            "-time" "2051222400" # Signature verification time: Jan  1 00:00:00 2035 GMT
            "-CAfile" "${CERTS}/CACert.pem"
            "-TSA-CAfile" "${CERTS}/TSACA.pem"
            "-in" "${FILES}/ts_cert.${ext}")
        set_tests_properties(
            verify_ts_future_${ext}
            PROPERTIES
            DEPENDS "sign_ts_cert_${ext}"
            REQUIRED_FILES "${FILES}/ts_cert.${ext}"
            REQUIRED_FILES "${LOGS}/port.log")
    endforeach(ext ${extensions_3})

    # Tests 96-98
    # Verify with ignored timestamp
    # This tests are expected to fail
    foreach(ext ${extensions_3})
        add_test(
            NAME verify_ts_ignore_${ext}
            COMMAND osslsigncode "verify"
            "-time" "2051222400" # Signature verification time: Jan  1 00:00:00 2035 GMT
            "-ignore-timestamp"
            "-CAfile" "${CERTS}/CACert.pem"
            "-TSA-CAfile" "${CERTS}/TSACA.pem"
            "-in" "${FILES}/ts_cert.${ext}")
        set_tests_properties(
            verify_ts_ignore_${ext}
            PROPERTIES
            DEPENDS "sign_ts_cert_${ext}"
            REQUIRED_FILES "${FILES}/ts_cert.${ext}"
            REQUIRED_FILES "${LOGS}/port.log"
            WILL_FAIL TRUE)
    endforeach(ext ${extensions_3})


### Verify CRL Distribution Points ###

    # Tests 99-101
    # Verify file signed with X509v3 CRL Distribution Points extension
    # Signature verification time: Sep  1 00:00:00 2019 GMT
    # Check X509v3 CRL Distribution Points extension, don't use "-CRLfile" and "-TSA-CRLfile" options
    foreach(ext ${extensions_3})
        add_test(
            NAME verify_ts_cert_crldp_${ext}
            COMMAND osslsigncode "verify"
            "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
            "-CAfile" "${CERTS}/CACert.pem"
            "-TSA-CAfile" "${CERTS}/TSACA.pem"
            "-in" "${FILES}/ts_cert_crldp.${ext}")
        set_tests_properties(
            verify_ts_cert_crldp_${ext}
            PROPERTIES
            DEPENDS "sign_ts_cert_crldp_${ext}"
            REQUIRED_FILES "${FILES}/ts_cert_crldp.${ext}"
            REQUIRED_FILES "${LOGS}/port.log")
    endforeach(ext ${extensions_3})

    # Tests 102-107
    # Verify with expired or revoked certificate without X509v3 CRL Distribution Points extension
    # This tests are expected to fail
    set(failed_certs "expired" "revoked")
    foreach(ext ${extensions_3})
        foreach(cert ${failed_certs})
            add_test(
                NAME verify_ts_${cert}_${ext}
                COMMAND osslsigncode "verify"
                "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                "-CAfile" "${CERTS}/CACert.pem"
                "-CRLfile" "${CERTS}/CACertCRL.pem"
                "-TSA-CAfile" "${CERTS}/TSACA.pem"
                "-in" "${FILES}/ts_${cert}.${ext}")
            set_tests_properties(
                verify_ts_${cert}_${ext}
                PROPERTIES
                DEPENDS "sign_ts_${cert}_${ext}"
                REQUIRED_FILES "${FILES}/ts_${cert}.${ext}"
                REQUIRED_FILES "${LOGS}/port.log"
                WILL_FAIL TRUE)
        endforeach(cert ${failed_certs})
    endforeach(ext ${extensions_3})

    # Tests 108-110
    # Verify with revoked certificate contains X509v3 CRL Distribution Points extension
    # Check X509v3 CRL Distribution Points extension, don't use "-CRLfile" and "-TSA-CRLfile" options
    # This test is expected to fail
    foreach(ext ${extensions_3})
        add_test(
            NAME verify_ts_revoked_crldp_${ext}
            COMMAND osslsigncode "verify"
            "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
            "-CAfile" "${CERTS}/CACert.pem"
            "-TSA-CAfile" "${CERTS}/TSACA.pem"
            "-in" "${FILES}/ts_revoked_crldp.${ext}")
        set_tests_properties(
            verify_ts_revoked_crldp_${ext}
            PROPERTIES
            DEPENDS "sign_ts_revoked_crldp_${ext}"
            REQUIRED_FILES "${FILES}/ts_revoked_crldp.${ext}"
            REQUIRED_FILES "${LOGS}/port.log"
            WILL_FAIL TRUE)
    endforeach(ext ${extensions_3})


### Cleanup ###

    # Test 111
    # Stop HTTP server
    if(STOP_SERVER)
        add_test(NAME stop_server
        COMMAND ${Python3_EXECUTABLE} "${CLIENT_HTTP}")
        set_tests_properties(
            stop_server
            PROPERTIES
            REQUIRED_FILES "${LOGS}/port.log")
    else(STOP_SERVER)
        message(STATUS "Keep HTTP server after tests")
    endif(STOP_SERVER)

else(Python3_FOUND OR server_error)
    message(STATUS "CTest skips some tests")
endif(Python3_FOUND OR server_error)


# Test 112
# Delete test files
foreach(ext ${extensions_4})
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/legacy.${ext}")
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/signed.${ext}")
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/signed_crldp.${ext}")
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/nested.${ext}")
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/revoked.${ext}")
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/removed.${ext}")
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/added.${ext}")
    foreach(cert ${pem_certs})
        set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/ts_${cert}.${ext}")
    endforeach(cert ${pem_certs})
    foreach(format ${formats})
        set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/${ext}.${format}")
        set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/${ext}.${format}")
        set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/attached_${format}.${ext}")
    endforeach(format ${formats})
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/jreq.tsq")
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/jresp.tsr")
endforeach(ext ${extensions_4})

add_test(NAME remove_files
    COMMAND ${CMAKE_COMMAND} -E rm -f ${OUTPUT_FILES})

#[[
Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
]]
