# make test
# ctest -C Release

include(FindPython3)
enable_testing()

set(FILES "${PROJECT_BINARY_DIR}/Testing/files")
set(CERTS "${PROJECT_BINARY_DIR}/Testing/certs")
set(CONF "${PROJECT_BINARY_DIR}/Testing/conf")

file(COPY
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/files"
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/conf"
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/tsa_server.py"
  DESTINATION "${PROJECT_BINARY_DIR}/Testing"
)

file(COPY
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/ca-bundle.crt"
  DESTINATION "${CONF}"
)

set(priv_p12 "-pkcs12" "${CERTS}/cert.p12" "-readpass" "${CERTS}/password.txt")
set(priv_spc "-certs" "${CERTS}/cert.spc" "-key" "${CERTS}/key.pvk" "-pass" "passme")
set(priv_der "-certs" "${CERTS}/cert.pem" "-key" "${CERTS}/key.der" "-pass" "passme")
set(priv_pkey "-certs" "${CERTS}/cert.pem" "-key" "${CERTS}/keyp.pem" "-pass" "passme")
set(sign_opt "-time" "1556708400"
  "-add-msi-dse" "-comm" "-ph" "-jp" "low"
  "-h" "sha512" "-i" "https://www.osslsigncode.com/"
  "-n" "osslsigncode" "-ac" "${CERTS}/crosscert.pem"
)

if(NOT CMAKE_HOST_WIN32)
  execute_process(
    COMMAND "${CONF}/makecerts.sh"
    WORKING_DIRECTORY ${CONF}
    OUTPUT_VARIABLE makecerts_output
    RESULT_VARIABLE makecerts_result
  )
else()
  set(makecerts_result 1)
endif()
if(makecerts_result)
  message(STATUS "makecerts.sh failed")
  if(makecerts_output)
    message(STATUS "${makecerts_output}")
  endif()
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs"
    DESTINATION "${PROJECT_BINARY_DIR}/Testing"
  )
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E sha256sum "${CERTS}/cert.der"
  OUTPUT_VARIABLE sha256sum
)
string(SUBSTRING ${sha256sum} 0 64 leafhash)
set(verify_opt "-CAfile" "${CERTS}/CACert.pem"
  "-CRLfile" "${CERTS}/CACertCRL.pem"
  "-TSA-CAfile" "${CERTS}/TSACA.pem"
)
set(extensions_4 "exe" "ex_" "msi" "cat")
set(extensions_3 "exe" "ex_" "msi")
set(files_4 "signed" "nested" "added")
set(files_3 "removed" "attached_pem" "attached_der")
set(sign_formats "pem" "der")
set(pem_certs "cert" "expired" "revoked")
set(failed_certs "expired" "revoked")

add_test(
  NAME version
  COMMAND osslsigncode --version
)

foreach(ext ${extensions_4})
  # Signing time: May  1 00:00:00 2019 GMT
  set(sign_${ext} )
  add_test(
    NAME signed_${ext}
    COMMAND osslsigncode "sign" ${sign_opt} ${priv_p12}
      "-in" "${FILES}/unsigned.${ext}" "-out" "${FILES}/signed.${ext}"
  )
endforeach()

foreach(ext ${extensions_3})
  add_test(
    NAME removed_${ext}
    COMMAND osslsigncode "remove-signature"
      "-in" "${FILES}/signed.${ext}" "-out" "${FILES}/removed.${ext}"
  )
endforeach()

foreach(ext ${extensions_3})
  add_test(
    NAME extract_pem_${ext}
    COMMAND osslsigncode "extract-signature" "-pem"
      "-in" "${FILES}/signed.${ext}" "-out" "${FILES}/${ext}.pem"
  )
endforeach()

foreach(ext ${extensions_3})
  add_test(
    NAME extract_der_${ext}
    COMMAND osslsigncode "extract-signature"
      "-in" "${FILES}/signed.${ext}" "-out" "${FILES}/${ext}.der"
  )
endforeach()

foreach(ext ${extensions_3})
  set_tests_properties(removed_${ext} extract_pem_${ext} extract_der_${ext}
    PROPERTIES DEPENDS sign_${ext}
    REQUIRED_FILES "${FILES}/signed.${ext}"
  )
endforeach()

foreach(ext ${extensions_3})
  foreach(format ${sign_formats})
    # Signature verification time: Sep  1 00:00:00 2019 GMT
    add_test(
      NAME attached_${format}_${ext}
      COMMAND osslsigncode "attach-signature" ${verify_opt}
        "-time" "1567296000"
        "-require-leaf-hash" "SHA256:${leafhash}"
        "-add-msi-dse" "-h" "sha512" "-nest"
        "-sigin" "${FILES}/${ext}.${format}"
        "-in" "${FILES}/signed.${ext}" "-out" "${FILES}/attached_${format}.${ext}"
      )
      set_tests_properties(attached_${format}_${ext} PROPERTIES
        DEPENDS extract_pem_${ext}
        REQUIRED_FILES "${FILES}/signed.${ext}"
        REQUIRED_FILES "${FILES}/${ext}.${format}"
      )
  endforeach()
endforeach()

foreach(ext ${extensions_4})
  add_test(
    NAME added_${ext}
    COMMAND osslsigncode "add"
      "-addUnauthenticatedBlob" "-add-msi-dse" "-h" "sha512"
      "-in" "${FILES}/signed.${ext}" "-out" "${FILES}/added.${ext}"
  )
  set_tests_properties(added_${ext} PROPERTIES
    DEPENDS sign_${ext}
    REQUIRED_FILES "${FILES}/signed.${ext}"
  )
endforeach()

foreach(ext ${extensions_4})
  add_test(
    NAME nested_${ext}
    COMMAND osslsigncode "sign" "-nest" ${sign_opt} ${priv_der}
      "-in" "${FILES}/signed.${ext}" "-out" "${FILES}/nested.${ext}"
  )
  set_tests_properties(nested_${ext} PROPERTIES
    DEPENDS sign_${ext}
    REQUIRED_FILES "${FILES}/signed.${ext}"
  )
endforeach()


foreach(file ${files_4})
  foreach(ext ${extensions_4})
    # Signature verification time: Sep  1 00:00:00 2019 GMT
    add_test(
      NAME verify_${file}_${ext}
      COMMAND osslsigncode "verify" ${verify_opt}
        "-time" "1567296000"
        "-require-leaf-hash" "SHA256:${leafhash}"
        "-in" "${FILES}/${file}.${ext}"
    )
    set_tests_properties(verify_${file}_${ext} PROPERTIES
      DEPENDS ${file}_${ext}
      REQUIRED_FILES "${FILES}/${file}.${ext}"
    )
  endforeach()
endforeach()

foreach(file ${files_3})
  foreach(ext ${extensions_3})
    # Signature verification time: Sep  1 00:00:00 2019 GMT
    add_test(
      NAME verify_${file}_${ext}
      COMMAND osslsigncode "verify" ${verify_opt}
        "-time" "1567296000"
        "-require-leaf-hash" "SHA256:${leafhash}"
        "-in" "${FILES}/${file}.${ext}"
    )
    set_tests_properties(verify_${file}_${ext} PROPERTIES
      DEPENDS ${file}_${ext}
      REQUIRED_FILES "${FILES}/${file}.${ext}"
    )
  endforeach()
endforeach()

foreach(ext ${extensions_3})
  set_tests_properties(verify_removed_${ext} PROPERTIES
    WILL_FAIL TRUE
  )
endforeach()


if(Python3_FOUND)
  foreach(ext ${extensions_4})
    foreach(cert ${pem_certs})
      add_test(
        NAME sign_ts_${cert}_${ext}
        COMMAND ${Python3_EXECUTABLE} "${PROJECT_BINARY_DIR}/Testing/tsa_server.py"
          "--bindir" "${PROJECT_BINARY_DIR}/${CMAKE_DEFAULT_BUILD_TYPE}"
          "--certs" "${CERTS}/${cert}.pem" "--key" "${CERTS}/key.pem"
          "--input" "${FILES}/unsigned.${ext}" "--output" "${FILES}/ts_${cert}.${ext}"
      )
    endforeach()
  endforeach()

  foreach(ext ${extensions_4})
    # Signature verification time: Sep  1 00:00:00 2019 GMT
    add_test(
      NAME verify_ts_cert_${ext}
      COMMAND osslsigncode "verify" ${verify_opt}
        "-time" "1567296000"
        "-in" "${FILES}/ts_cert.${ext}"
    )
    set_tests_properties(verify_ts_cert_${ext} PROPERTIES
      DEPENDS sign_ts_${cert}_${ext}
      REQUIRED_FILES "${FILES}/ts_cert.${ext}"
    )
  endforeach()

  # Signature verification time: Jan  1 00:00:00 2035 GMT
  foreach(ext ${extensions_4})
    add_test(
      NAME verify_ts_future_${ext}
      COMMAND osslsigncode "verify" ${verify_opt}
        "-time" "2051222400"
        "-in" "${FILES}/ts_cert.${ext}"
    )
    set_tests_properties(verify_ts_future_${ext} PROPERTIES
      DEPENDS sign_ts_${cert}_${ext}
      REQUIRED_FILES "${FILES}/ts_cert.${ext}"
    )
  endforeach()

  # Signature verification time: Jan  1 00:00:00 2035 GMT
  # enabled "-ignore-timestamp" option
  foreach(ext ${extensions_4})
    add_test(
      NAME verify_ts_ignore_${ext}
      COMMAND osslsigncode "verify" ${verify_opt}
        "-time" "2051222400"
        "-ignore-timestamp"
        "-in" "${FILES}/ts_cert.${ext}"
    )
    set_tests_properties(verify_ts_ignore_${ext} PROPERTIES
      DEPENDS sign_ts_${cert}_${ext}
      REQUIRED_FILES "${FILES}/ts_cert.${ext}"
      WILL_FAIL TRUE
    )
  endforeach()

  # Signature verification time: Sep  1 00:00:00 2019 GMT
  # Certificate has expired or revoked
  foreach(ext ${extensions_4})
    foreach(cert ${failed_certs})
      add_test(
        NAME verify_ts_${cert}_${ext}
        COMMAND osslsigncode "verify" ${verify_opt}
          "-time" "1567296000"
          "-in" "${FILES}/ts_${cert}.${ext}"
      )
      set_tests_properties(verify_ts_${cert}_${ext} PROPERTIES
        DEPENDS sign_ts_${cert}_${ext}
        REQUIRED_FILES "${FILES}/ts_${cert}.${ext}"
        WILL_FAIL TRUE
      )
    endforeach()
  endforeach()

else()
  message(STATUS "Python3 was not found, skip timestamping tests")
endif()

foreach(ext ${extensions_4})
  set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/signed.${ext}")
  set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/nested.${ext}")
  set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/removed.${ext}")
  set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/added.${ext}")
  foreach(cert ${pem_certs})
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/ts_${cert}.${ext}")
  endforeach()
  foreach(format ${sign_formats})
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/${ext}.${format}")
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/${ext}.${format}")
    set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/attached_${format}.${ext}")
  endforeach()
  set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/jreq.tsq")
  set(OUTPUT_FILES ${OUTPUT_FILES} "${FILES}/jresp.tsr")
endforeach()
add_test(NAME remove_files COMMAND ${CMAKE_COMMAND} -E rm -f ${OUTPUT_FILES})
