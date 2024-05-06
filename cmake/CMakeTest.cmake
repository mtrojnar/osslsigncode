# make test
# ctest -C Release

########## Configure ##########

include(FindPython3)

if(Python3_FOUND)
    execute_process(
        COMMAND ${Python3_EXECUTABLE} "check_cryptography.py"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        OUTPUT_VARIABLE cryptography_output
        RESULT_VARIABLE cryptography_error)

    if(NOT cryptography_error)
        message(STATUS "Using python3-cryptography version ${cryptography_output}")
        option(STOP_SERVER "Stop HTTP server after tests" ON)

        # Remove http proxy configuration that may change behavior
        unset(ENV{HTTP_PROXY})
        unset(ENV{http_proxy})

        set(TEST_DIR "${PROJECT_BINARY_DIR}/Testing")
        if(CMAKE_GENERATOR STREQUAL "Ninja Multi-Config")
            set(OSSLSIGNCODE "${PROJECT_BINARY_DIR}/${CMAKE_BUILD_TYPE}/osslsigncode")
        else(CMAKE_GENERATOR STREQUAL "Ninja Multi-Config")
            set(OSSLSIGNCODE "${PROJECT_BINARY_DIR}/osslsigncode")
        endif(CMAKE_GENERATOR STREQUAL "Ninja Multi-Config")
        set(EXEC "${TEST_DIR}/exec.py")
        set(FILES "${TEST_DIR}/files")
        set(CERTS "${TEST_DIR}/certs")
        set(CONF "${TEST_DIR}/conf")
        set(LOGS "${TEST_DIR}/logs")

        file(MAKE_DIRECTORY "${LOGS}")

        file(COPY
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/ca-bundle.crt"
            DESTINATION "${CONF}")

        file(COPY
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/files"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/conf"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/client_http.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/make_certificates.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/calc_leafhash.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/exec.py"
            DESTINATION "${TEST_DIR}/")

        if(UNIX)
            file(COPY
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/server_http.py"
                DESTINATION "${TEST_DIR}/")
            set(SERVER_HTTP "${TEST_DIR}/server_http.py")
            set(Python3w_EXECUTABLE ${Python3_EXECUTABLE})
        else(UNIX)
            file(COPY
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/server_http.pyw"
                DESTINATION "${TEST_DIR}/")
            set(SERVER_HTTP "${TEST_DIR}/server_http.pyw")
            get_filename_component(PYTHON_DIRECTORY ${Python3_EXECUTABLE} DIRECTORY)
			set(Python3w_EXECUTABLE "${PYTHON_DIRECTORY}/pythonw.exe")
			message(STATUS "Python3w_EXECUTABLE ${Python3w_EXECUTABLE}")
        endif(UNIX)

        if(EXISTS "${LOGS}/url.log")
            # Stop HTTP server if running
            message(STATUS "Try to kill HTTP server")
            execute_process(
                COMMAND ${Python3_EXECUTABLE} "${TEST_DIR}/client_http.py"
                OUTPUT_VARIABLE client_output
                RESULT_VARIABLE client_result)
            if(NOT client_result)
                # Successfully closed
                message(STATUS "${client_output}")
            endif(NOT client_result)
        endif(EXISTS "${LOGS}/url.log")

    set(extensions_all "exe" "ex_" "msi" "256appx" "512appx" "cat" "ps1" "psc1" "mof")
    set(extensions_nocat "exe" "ex_" "msi" "256appx" "512appx" "ps1" "psc1" "mof")
    set(extensions_nocatappx "exe" "ex_" "msi" "ps1" "psc1" "mof")
    set(formats "pem" "der")

    else(NOT cryptography_error)
        message(STATUS "CTest skips tests: ${cryptography_output}")
    endif(NOT cryptography_error)

else(Python3_FOUND)
    message(STATUS "CTest skips tests: Python3 not found")
endif(Python3_FOUND)


########## Testing ##########

enable_testing()

### osslsigncode version ###
if(Python3_FOUND AND NOT cryptography_error)

### Start ###
    add_test(NAME "version"
        COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE}
        "--version")

    add_test(NAME "start_server"
        COMMAND ${Python3w_EXECUTABLE} ${SERVER_HTTP})
    set_tests_properties("start_server" PROPERTIES
        SKIP_RETURN_CODE 1
        TIMEOUT 60)

    add_test(NAME "calc_leafhash"
        COMMAND ${Python3_EXECUTABLE} "${TEST_DIR}/calc_leafhash.py")
    set_tests_properties("calc_leafhash" PROPERTIES
        DEPENDS "start_server"
        TIMEOUT 60)

    set(ALL_TESTS "version" "start_server" "calc_leafhash")

### Sign ###

    # Sign with PKCS#12 container with private key and certificate encryption algorithm
    # Signing time: May  1 00:00:00 2019 GMT (1556668800)
    foreach(ext ${extensions_all})
        add_test(NAME "signed_${ext}"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "sign"
            "-pkcs12" "${CERTS}/cert.p12"
            "-readpass" "${CERTS}/password.txt"
            "-ac" "${CERTS}/CAcross.pem"
            "-time" "1556668800"
            "-add-msi-dse"
            "-comm"
            "-ph"
            "-jp" "low"
            "-h" "sha512" "-i" "https://www.osslsigncode.com/"
            "-n" "osslsigncode"
            "-in" "${FILES}/unsigned.${ext}"
            "-out" "${FILES}/signed.${ext}")
        set_tests_properties("signed_${ext}" PROPERTIES
            DEPENDS "calc_leafhash")
        list(APPEND ALL_TESTS "signed_${ext}")
    endforeach(ext ${extensions_all})

    # Sign with revoked certificate
    foreach(ext ${extensions_all})
        add_test(NAME "revoked_${ext}"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "sign"
            "-certs" "${CERTS}/revoked.pem"
            "-key" "${CERTS}/keyp.pem"
            "-readpass" "${CERTS}/password.txt"
            "-ac" "${CERTS}/CAcross.pem"
            "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
            "-add-msi-dse"
            "-comm"
            "-ph"
            "-jp" "low"
            "-h" "sha512" "-i" "https://www.osslsigncode.com/"
            "-n" "osslsigncode"
            "-in" "${FILES}/unsigned.${ext}"
            "-out" "${FILES}/revoked.${ext}")
        set_tests_properties("revoked_${ext}" PROPERTIES
            DEPENDS "calc_leafhash")
        list(APPEND ALL_TESTS "revoked_${ext}")
    endforeach(ext ${extensions_all})

    # Remove signature
    # Unsupported command for CAT files
    foreach(ext ${extensions_nocat})
        add_test(NAME "removed_${ext}"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "remove-signature"
            "-in" "${FILES}/signed.${ext}"
            "-out" "${FILES}/removed.${ext}")
        set_tests_properties("removed_${ext}" PROPERTIES
            DEPENDS "signed_${ext}")
        list(APPEND ALL_TESTS "removed_${ext}")
    endforeach(ext ${extensions_nocat})

    # Extract PKCS#7 signature in PEM format
    foreach(ext ${extensions_all})
        add_test(NAME "extract_pem_${ext}"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "extract-signature"
            "-pem" # PEM format
            "-in" "${FILES}/signed.${ext}"
            "-out" "${FILES}/${ext}.pem")
        set_tests_properties("extract_pem_${ext}" PROPERTIES
            DEPENDS "signed_${ext}")
        list(APPEND ALL_TESTS "extract_pem_${ext}")
    endforeach(ext ${extensions_all})

    # Extract PKCS#7 signature in default DER format
    foreach(ext ${extensions_all})
        add_test(NAME "extract_der_${ext}"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "extract-signature"
            "-in" "${FILES}/signed.${ext}"
            "-out" "${FILES}/${ext}.der")
        set_tests_properties("extract_der_${ext}" PROPERTIES
            DEPENDS "signed_${ext}")
        list(APPEND ALL_TESTS "extract_der_${ext}")
    endforeach(ext ${extensions_all})

    # Attach a nested signature in PEM or DER format
    # Unsupported command for CAT files
    foreach(ext ${extensions_nocat})
        foreach(format ${formats})
            add_test(NAME "attached_${format}_${ext}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "attach-signature"
                # sign options
                "-add-msi-dse"
                "-h" "sha512"
                "-nest"
                "-sigin" "${FILES}/${ext}.${format}"
                "-in" "${FILES}/signed.${ext}"
                "-out" "${FILES}/attached_${format}.${ext}"
                # verify options
                "-require-leaf-hash" "FILE ${CERTS}/leafhash.txt"
                "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                "-CAfile" "${CERTS}/CACert.pem"
                "-CRLfile" "${CERTS}/CACertCRL.pem")
            set_tests_properties("attached_${format}_${ext}" PROPERTIES
                DEPENDS "signed_${ext};extract_pem_${ext};extract_der_${ext}")
            list(APPEND ALL_TESTS "attached_${format}_${ext}")
        endforeach(format ${formats})
    endforeach(ext ${extensions_nocat})

    # Add an unauthenticated blob to a previously-signed file
    foreach(ext ${extensions_all})
        add_test(NAME "added_${ext}"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "add"
            "-addUnauthenticatedBlob"
            "-add-msi-dse" "-h" "sha512"
            "-in" "${FILES}/signed.${ext}"
            "-out" "${FILES}/added.${ext}")
        set_tests_properties("added_${ext}" PROPERTIES
            DEPENDS "signed_${ext}")
        list(APPEND ALL_TESTS "added_${ext}")
    endforeach(ext ${extensions_all})

    # Add the new nested signature instead of replacing the first one
    # APPX files do not support nesting (multiple signature)
    foreach(ext ${extensions_all})
        add_test(NAME "nested_${ext}"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "sign"
            "-nest"
            "-certs" "${CERTS}/cert.pem"
            "-key" "${CERTS}/key.der"
            "-pass" "passme"
            "-ac" "${CERTS}/CAcross.pem"
            "-time" "1556755200" # Signing time: May  2 00:00:00 2019 GMT
            "-add-msi-dse"
            "-comm"
            "-ph"
            "-jp" "low"
            "-h" "sha512"
            "-i" "https://www.osslsigncode.com/"
            "-n" "osslsigncode"
            "-in" "${FILES}/signed.${ext}"
            "-out" "${FILES}/nested.${ext}")
        set_tests_properties("nested_${ext}" PROPERTIES
            DEPENDS "signed_${ext}")
        list(APPEND ALL_TESTS "nested_${ext}")
    endforeach(ext ${extensions_all})


### Verify signature ###

    # Verify PE/MSI/CAB files signed in the catalog file
    # CAT and APPX files do not support detached PKCS#7 signature
    foreach(ext ${extensions_nocatappx})
        add_test(NAME "verify_catalog_${ext}"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
            "-catalog" "${FILES}/signed.cat" # catalog file
            "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
            "-require-leaf-hash" "FILE ${CERTS}/leafhash.txt"
            "-CAfile" "${CERTS}/CACert.pem"
            "-CRLfile" "${CERTS}/CACertCRL.pem"
            "-in" "${FILES}/unsigned.${ext}")
        set_tests_properties("verify_catalog_${ext}" PROPERTIES
            DEPENDS "signed_${ext}")
        list(APPEND ALL_TESTS "verify_catalog_${ext}")
    endforeach(ext ${extensions_nocatappx})

    # Verify signature
    set(files "signed" "nested" "added" "revoked")
    foreach(file ${files})
        foreach(ext ${extensions_all})
            add_test(NAME "verify_${file}_${ext}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
                "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                "-CAfile" "${CERTS}/CACert.pem"
                "-CRLfile" "${CERTS}/CACertCRL.pem"
                "-in" "${FILES}/${file}.${ext}")
            set_tests_properties("verify_${file}_${ext}" PROPERTIES
                DEPENDS "${file}_${ext}")
            list(APPEND ALL_TESTS "verify_${file}_${ext}")
        endforeach(ext ${extensions_all})
    endforeach(file ${files})

    # "revoked" tests are expected to fail
    set(files "revoked")
    foreach(file ${files})
        foreach(ext ${extensions_all})
            set_tests_properties("verify_${file}_${ext}" PROPERTIES
                WILL_FAIL TRUE)
        endforeach(ext ${extensions_all})
    endforeach(file ${files})

    # Verify removed signature
    # "removed" tests are expected to fail
    # "remove-signature" command is unsupported for CAT files
    set(files "removed")
    foreach(file ${files})
        foreach(ext ${extensions_nocat})
            add_test(NAME "verify_${file}_${ext}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
                "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                "-CAfile" "${CERTS}/CACert.pem"
                "-CRLfile" "${CERTS}/CACertCRL.pem"
                "-in" "${FILES}/${file}.${ext}")
            set_tests_properties("verify_${file}_${ext}" PROPERTIES
                DEPENDS "${file}_${ext}"
                WILL_FAIL TRUE)
            list(APPEND ALL_TESTS "verify_${file}_${ext}")
        endforeach(ext ${extensions_nocat})
    endforeach(file ${files})

    # Verify attached signature
    # "attach-signature" command is unsupported for CAT files
    set(files "attached_pem" "attached_der")
    foreach(file ${files})
        foreach(ext ${extensions_nocat})
            add_test(NAME "verify_${file}_${ext}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
                "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                "-CAfile" "${CERTS}/CACert.pem"
                "-CRLfile" "${CERTS}/CACertCRL.pem"
                "-in" "${FILES}/${file}.${ext}")
            set_tests_properties("verify_${file}_${ext}" PROPERTIES
                DEPENDS "${file}_${ext}")
            list(APPEND ALL_TESTS "verify_${file}_${ext}")
        endforeach(ext ${extensions_nocat})
    endforeach(file ${files})


### Extract a data content to be signed ###

    # Unsupported command "extract-data" for CAT files
    foreach(ext ${extensions_nocat})
        # Extract PKCS#7 with data content, output in PEM format
        add_test(NAME "data_${ext}_pem"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "extract-data"
            "-ph"
            "-h" "sha384"
            "-add-msi-dse"
            "-pem" # PEM format
            "-in" "${FILES}/unsigned.${ext}"
            "-out" "${FILES}/data_${ext}.pem")

        # Extract PKCS#7 with data content, output in default DER format
        add_test(NAME "data_${ext}_der"
            COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "extract-data"
            "-ph"
            "-h" "sha384"
            "-add-msi-dse"
            "-in" "${FILES}/unsigned.${ext}"
            "-out" "${FILES}/data_${ext}.der")

        foreach(data_format ${formats})
            set_tests_properties("data_${ext}_${data_format}" PROPERTIES
                DEPENDS "calc_leafhash")
            list(APPEND ALL_TESTS "data_${ext}_${data_format}")
        endforeach(data_format ${formats})

        # Sign a data content, output in DER format
        foreach(data_format ${formats})
            add_test(NAME "signed_data_${ext}_${data_format}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "sign"
                "-pkcs12" "${CERTS}/cert.p12"
                "-readpass" "${CERTS}/password.txt"
                "-ac" "${CERTS}/CAcross.pem"
                "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
                "-add-msi-dse"
                "-comm"
                "-ph"
                "-jp" "low"
                "-h" "sha384"
                "-i" "https://www.osslsigncode.com/"
                "-n" "osslsigncode"
                "-in" "${FILES}/data_${ext}.${data_format}"
                "-out" "${FILES}/signed_data_${ext}_${data_format}.der")
            set_tests_properties("signed_data_${ext}_${data_format}" PROPERTIES
                DEPENDS "data_${ext}_pem;data_${ext}_der")
            list(APPEND ALL_TESTS "signed_data_${ext}_${data_format}")
        endforeach(data_format ${formats})

        # Sign a data content, output in PEM format
        foreach(data_format ${formats})
            add_test(NAME "signed_data_pem_${ext}_${data_format}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "sign"
                "-pkcs12" "${CERTS}/cert.p12"
                "-readpass" "${CERTS}/password.txt"
                "-ac" "${CERTS}/CAcross.pem"
                "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
                "-add-msi-dse"
                "-comm"
                "-ph"
                "-jp" "low"
                "-h" "sha384"
                "-i" "https://www.osslsigncode.com/"
                "-n" "osslsigncode"
                "-pem" # PEM format
                "-in" "${FILES}/data_${ext}.${data_format}"
                "-out" "${FILES}/signed_data_${ext}_${data_format}.pem")
            set_tests_properties("signed_data_pem_${ext}_${data_format}" PROPERTIES
                DEPENDS "data_${ext}_${data_format}")
            list(APPEND ALL_TESTS "signed_data_pem_${ext}_${data_format}")
       endforeach(data_format ${formats})

        # Attach signature in PEM or DER format
        foreach(data_format ${formats})
            foreach(format ${formats})
                add_test(NAME "attached_data_${ext}_${data_format}_${format}"
                    COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "attach-signature"
                    # sign options
                    "-add-msi-dse"
                    "-h" "sha384"
                    "-sigin" "${FILES}/signed_data_${ext}_${data_format}.${format}"
                    "-in" "${FILES}/unsigned.${ext}"
                    "-out" "${FILES}/attached_data_${data_format}_${format}.${ext}"
                    # verify options
                    "-require-leaf-hash" "FILE ${CERTS}/leafhash.txt"
                    "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                    "-CAfile" "${CERTS}/CACert.pem"
                    "-CRLfile" "${CERTS}/CACertCRL.pem")
                set_tests_properties("attached_data_${ext}_${data_format}_${format}" PROPERTIES
                    DEPENDS "signed_data_${ext}_${data_format};signed_data_pem_${ext}_${data_format}")
                list(APPEND ALL_TESTS "attached_data_${ext}_${data_format}_${format}")
            endforeach(format ${formats})
        endforeach(data_format ${formats})
    endforeach(ext ${extensions_nocat})


    if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0.0" OR CURL_FOUND)

### Sign with Time-Stamp Authority ###

        # Sign with the RFC3161 Time-Stamp Authority
        set(pem_certs "cert" "expired" "revoked")
        foreach(ext ${extensions_all})
            foreach(cert ${pem_certs})
                add_test(NAME "sign_ts_${cert}_${ext}"
                    COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "sign"
                    "-certs" "${CERTS}/${cert}.pem"
                    "-key" "${CERTS}/key.pem"
                    "-ac" "${CERTS}/CAcross.pem"
                    "-comm"
                    "-ph"
                    "-jp" "low"
                    "-h" "sha384"
                    "-i" "https://www.osslsigncode.com/"
                    "-n" "osslsigncode"
                    "-time" "1556668800" # Signing time: May  1 00:00:00 2019 GMT
                    "-ts" "FILE ${LOGS}/url.log"
                    "-in" "${FILES}/unsigned.${ext}"
                    "-out" "${FILES}/ts_${cert}.${ext}")
                set_tests_properties("sign_ts_${cert}_${ext}" PROPERTIES
                    ENVIRONMENT "HTTP_PROXY=;http_proxy="
                    DEPENDS "calc_leafhash")
                list(APPEND ALL_TESTS "sign_ts_${cert}_${ext}")
            endforeach(cert ${pem_certs})
        endforeach(ext ${extensions_all})


### Verify Time-Stamp Authority ###

        # Signature verification time: Sep  1 00:00:00 2019 GMT
        foreach(ext ${extensions_all})
            add_test(NAME "verify_ts_cert_${ext}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
                "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                "-CAfile" "${CERTS}/CACert.pem"
                "-TSA-CAfile" "${CERTS}/TSACA.pem"
                "-in" "${FILES}/ts_cert.${ext}")
            set_tests_properties("verify_ts_cert_${ext}" PROPERTIES
                ENVIRONMENT "HTTP_PROXY=;http_proxy=;"
                DEPENDS "sign_ts_cert_${ext}")
            list(APPEND ALL_TESTS "verify_ts_cert_${ext}")
        endforeach(ext ${extensions_all})

        # Signature verification time: Jan  1 00:00:00 2035 GMT
        foreach(ext ${extensions_all})
            add_test(NAME "verify_ts_future_${ext}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
                "-time" "2051222400" # Signature verification time: Jan  1 00:00:00 2035 GMT
                "-CAfile" "${CERTS}/CACert.pem"
                "-TSA-CAfile" "${CERTS}/TSACA.pem"
                "-in" "${FILES}/ts_cert.${ext}")
            set_tests_properties("verify_ts_future_${ext}" PROPERTIES
                ENVIRONMENT "HTTP_PROXY=;http_proxy=;"
                DEPENDS "sign_ts_cert_${ext}")
            list(APPEND ALL_TESTS "verify_ts_future_${ext}")
        endforeach(ext ${extensions_all})

        # Verify with ignored timestamp
        # This tests are expected to fail
        foreach(ext ${extensions_all})
            add_test(NAME "verify_ts_ignore_${ext}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
                "-time" "2051222400" # Signature verification time: Jan  1 00:00:00 2035 GMT
                "-ignore-timestamp"
                "-CAfile" "${CERTS}/CACert.pem"
                "-TSA-CAfile" "${CERTS}/TSACA.pem"
                "-in" "${FILES}/ts_cert.${ext}")
            set_tests_properties("verify_ts_ignore_${ext}" PROPERTIES
                ENVIRONMENT "HTTP_PROXY=;http_proxy=;"
                DEPENDS "sign_ts_cert_${ext}"
                WILL_FAIL TRUE)
            list(APPEND ALL_TESTS "verify_ts_ignore_${ext}")
        endforeach(ext ${extensions_all})


### Verify CRL Distribution Points ###

        # Verify file signed with X509v3 CRL Distribution Points extension
        # Signature verification time: Sep  1 00:00:00 2019 GMT
        # Check X509v3 CRL Distribution Points extension, don't use "-CRLfile" and "-TSA-CRLfile" options
        foreach(ext ${extensions_all})
            add_test(NAME "verify_ts_cert_crldp_${ext}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
                "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                "-CAfile" "${CERTS}/CACert.pem"
                "-TSA-CAfile" "${CERTS}/TSACA.pem"
                "-in" "${FILES}/ts_cert.${ext}")
            set_tests_properties("verify_ts_cert_crldp_${ext}" PROPERTIES
                ENVIRONMENT "HTTP_PROXY=;http_proxy=;"
                DEPENDS "sign_ts_cert_${ext}")
            list(APPEND ALL_TESTS "verify_ts_cert_crldp_${ext}")
        endforeach(ext ${extensions_all})

        # Verify with expired or revoked certificate, ignore X509v3 CRL Distribution Points extension
        # This tests are expected to fail
        set(failed_certs "expired" "revoked")
        foreach(ext ${extensions_all})
            foreach(cert ${failed_certs})
                add_test(NAME "verify_ts_${cert}_${ext}"
                    COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
                    "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                    "-CAfile" "${CERTS}/CACert.pem"
                    "-CRLfile" "${CERTS}/CACertCRL.pem"
                    "-ignore-cdp"
                    "-TSA-CAfile" "${CERTS}/TSACA.pem"
                    "-in" "${FILES}/ts_${cert}.${ext}")
                set_tests_properties("verify_ts_${cert}_${ext}" PROPERTIES
                    ENVIRONMENT "HTTP_PROXY=;http_proxy=;"
                    DEPENDS "sign_ts_${cert}_${ext}"
                    WILL_FAIL TRUE)
                list(APPEND ALL_TESTS "verify_ts_${cert}_${ext}")
            endforeach(cert ${failed_certs})
        endforeach(ext ${extensions_all})

        # Verify with revoked certificate contains X509v3 CRL Distribution Points extension
        # Check X509v3 CRL Distribution Points extension, don't use "-CRLfile" and "-TSA-CRLfile" options
        # This test is expected to fail
        foreach(ext ${extensions_all})
            add_test(NAME "verify_ts_revoked_crldp_${ext}"
                COMMAND ${Python3_EXECUTABLE} ${EXEC} ${OSSLSIGNCODE} "verify"
                "-time" "1567296000" # Signature verification time: Sep  1 00:00:00 2019 GMT
                "-CAfile" "${CERTS}/CACert.pem"
                "-TSA-CAfile" "${CERTS}/TSACA.pem"
                "-in" "${FILES}/ts_revoked.${ext}")
            set_tests_properties("verify_ts_revoked_crldp_${ext}" PROPERTIES
                ENVIRONMENT "HTTP_PROXY=;http_proxy=;"
                DEPENDS "sign_ts_revoked_${ext}"
                WILL_FAIL TRUE)
            list(APPEND ALL_TESTS "verify_ts_revoked_crldp_${ext}")
        endforeach(ext ${extensions_all})

### Cleanup ###
    # Stop HTTP server
        if(STOP_SERVER)
            add_test(NAME "stop_server"
            COMMAND ${Python3_EXECUTABLE} "${TEST_DIR}/client_http.py")
            set_tests_properties("stop_server" PROPERTIES
                DEPENDS "${ALL_TESTS}")
            list(APPEND ALL_TESTS "stop_server")
        else(STOP_SERVER)
            message(STATUS "Keep HTTP server after tests")
        endif(STOP_SERVER)

    else(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0.0" OR CURL_FOUND)
        message(STATUS "CTest skips some tests")
    endif(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0.0" OR CURL_FOUND)

    # Delete test files
    set(names "signed" "nested" "revoked" "removed" "added")
    foreach(ext ${extensions_all})
        foreach(name ${names})
            set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/${name}.${ext}")
        endforeach(name ${names})
        foreach(cert ${pem_certs})
            set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/ts_${cert}.${ext}")
        endforeach(cert ${pem_certs})
        foreach(format ${formats})
            set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/${ext}.${format}")
            set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/${ext}.${format}")
            set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/attached_${format}.${ext}")
            set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/data_${ext}.${format}")
            foreach(data_format ${formats})
                set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/signed_data_${ext}_${format}.${data_format}")
                set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/attached_data_${data_format}_${format}.${ext}")
            endforeach(data_format ${formats})
        endforeach(format ${formats})
        set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/jreq.tsq")
        set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/jresp.tsr")
    endforeach(ext ${extensions_all})

    add_test(NAME "remove_files"
        COMMAND ${CMAKE_COMMAND} -E rm -f ${OUTPUT_FILES})

    set_tests_properties("remove_files" PROPERTIES
        DEPENDS "${ALL_TESTS}")

endif(Python3_FOUND AND NOT cryptography_error)


#[[
Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
]]
