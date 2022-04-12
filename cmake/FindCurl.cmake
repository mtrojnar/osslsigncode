# find the native CURL headers and libraries

if(with-curl)
  if(curl-path)
    set(CURL_SEARCH_DIR PATHS ${CURL_ROOT} NO_DEFAULT_PATH)
    find_path(CURL_INCLUDE_DIRS
      NAMES curl/curl.h
      PATHS ${CURL_SEARCH_DIR}
      PATH_SUFFIXES include
      REQUIRED
    )
    find_library(CURL_LIBRARIES
      NAMES libcurl libcurl.so
      PATHS ${CURL_SEARCH_DIR}
      PATH_SUFFIXES lib
      NO_DEFAULT_PATH
      REQUIRED
    )
    mark_as_advanced(
      CURL_INCLUDE_DIRS
      CURL_LIBRARIES
    )
    set(CURL_FOUND TRUE)
  endif()

  if(CURL_FOUND)
    target_link_libraries(osslsigncode PRIVATE ${CURL_LIBRARIES})
    include_directories(${CURL_INCLUDE_DIRS})
    message(STATUS "Link CURL library: ${CURL_LIBRARIES}")
    message(STATUS "Include CURL directory: ${CURL_INCLUDE_DIRS}")
    set(ENABLE_CURL 1)
  else()
    MESSAGE(FATAL_ERROR "Could not find the CURL library and development files.")
  endif()

  if(MSVC)
    find_path(CURL_BIN_DIR
      NAMES curl.exe
      PATHS ${CURL_SEARCH_DIR}
      PATH_SUFFIXES bin
      REQUIRED
    )
    set(CURL_LIB "${CURL_BIN_DIR}/libcurl.dll")
  endif()
else()
  message(STATUS "Disable CURL")
endif()
