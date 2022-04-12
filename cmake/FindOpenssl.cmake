# find the OpenSSL encryption library

if(ssl-path)
  set(OPENSSL_SEARCH_DIR PATHS ${OPENSSL_ROOT} NO_DEFAULT_PATH)
  find_path(OPENSSL_INCLUDE_DIR
    NAMES openssl/opensslconf.h
    PATHS ${OPENSSL_SEARCH_DIR}
    PATH_SUFFIXES include
    REQUIRED
  )
  find_library(OPENSSL_SSL
    NAMES libssl libssl.so
    PATHS ${OPENSSL_SEARCH_DIR}
    PATH_SUFFIXES lib lib64
    NO_DEFAULT_PATH
    REQUIRED
  )
  find_library(OPENSSL_CRYPTO
    NAMES libcrypto libcrypto.so
    PATHS ${OPENSSL_SEARCH_DIR}
    PATH_SUFFIXES lib lib64
    NO_DEFAULT_PATH
    REQUIRED
  )

  if(MSVC)
    find_file(OPENSSL_APPLINK_SOURCE
      NAMES openssl/applink.c
      PATHS ${OPENSSL_INCLUDE_DIR}
      NO_DEFAULT_PATH
      REQUIRED
      )
  else()
    set(OPENSSL_APPLINK_SOURCE)
  endif()

  set(OPENSSL_LIBRARIES ${OPENSSL_SSL} ${OPENSSL_CRYPTO})
  mark_as_advanced(
    OPENSSL_INCLUDE_DIR
    OPENSSL_LIBRARIES
    OPENSSL_APPLINK_SOURCE
  )
  set(OPENSSL_FOUND TRUE)
endif()

if(OPENSSL_FOUND)
  message(STATUS "Link OpenSSL libraries: ${OPENSSL_LIBRARIES}")
  message(STATUS "Include OpenSSL directory: ${OPENSSL_INCLUDE_DIR}")
  if(MSVC)
    message(STATUS "OpenSSL applink source: ${OPENSSL_APPLINK_SOURCE}")
  endif()
else()
  MESSAGE(FATAL_ERROR "Could not find the OpenSSL library and development files.")
endif()

if(MSVC)
  find_path(OPENSSL_BIN_DIR
    NAMES openssl.exe
    PATHS ${OPENSSL_SEARCH_DIR}
    PATH_SUFFIXES bin
    REQUIRED
  )
  set(OPENSSL_LIBS "${OPENSSL_BIN_DIR}/libcrypto-3-x64.dll" "${OPENSSL_BIN_DIR}/libssl-3-x64.dll")
endif()

# add an executable target called "osslsigncode" to be built from the source files
set(SOURCE_FILES osslsigncode.c msi.c ${OPENSSL_APPLINK_SOURCE})
add_executable(osslsigncode)
target_sources(osslsigncode PRIVATE ${SOURCE_FILES})
target_link_libraries(osslsigncode PRIVATE ${OPENSSL_LIBRARIES})
include_directories(${OPENSSL_INCLUDE_DIR})
