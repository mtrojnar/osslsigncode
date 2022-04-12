# add command line options

# set Release build mode
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose Release or Debug" FORCE)
endif()

option(enable-strict "Enable strict compile mode" OFF)
option(enable-pedantic "Enable pedantic compile mode" OFF)
option(with-curl "Enable curl" ON)

if(MSVC)
  set(ssl-path "D:/TEMP/OpenSSL-3.0.2/vc-win64a" CACHE FILEPATH "OpenSSL library path")
  set(curl-path "D:/TEMP/curl-7.82.0" CACHE FILEPATH "cURL library path")
else()
  option(ssl-path "OpenSSL library path" OFF)
  option(curl-path "cURL library path" OFF)
endif()

if(ssl-path)
  set(OPENSSL_ROOT ${ssl-path})
  set(OPENSSL_SEARCH_DIR)
else()
  include(FindOpenSSL)
endif()

if(with-curl)
  if(curl-path)
    set(CURL_ROOT ${curl-path})
    set(CURL_BIN_DIR)
  else()
    include(FindCURL)
  endif()
endif()

# enable compile options
if(enable-strict)
  message(STATUS "Enable strict compile mode")
  if(MSVC)
    # Microsoft Visual C warning level
    add_compile_options(/Wall)
  else()
    add_compile_options(-Wall -Wextra)
  endif()
endif()

if(enable-pedantic)
  message(STATUS "Enable pedantic compile mode")
  if(MSVC)
    add_compile_options(/W4)
  else()
    add_compile_options(-pedantic)
  endif()
endif()
