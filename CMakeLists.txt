# required cmake version
cmake_minimum_required(VERSION 3.6)

# set the project name and version
project(osslsigncode VERSION 2.4)
set(DEV "-dev")
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}${DEV}")
set(PACKAGE_STRING "${PROJECT_NAME} ${PROJECT_VERSION}")
set(PACKAGE_BUGREPORT "Michal.Trojnara@stunnel.org")

# specify the C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# load CMake library modules
include(FindOpenSSL)
include(FindCURL)

# load CMake project modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")
include(FindMapping)

# define the target
add_executable(osslsigncode)

# create and use config.h
configure_file(Config.h.in config.h)
target_compile_definitions(osslsigncode PRIVATE HAVE_CONFIG_H=1)

# set sources
target_sources(osslsigncode PRIVATE osslsigncode.c msi.c)
if(WIN32)
target_sources(osslsigncode PRIVATE applink.c)
endif(WIN32)

# set include directories
target_include_directories(osslsigncode PRIVATE "${PROJECT_BINARY_DIR}")

# set OpenSSL includes/libraries
if(NOT OPENSSL_FOUND)
  message(FATAL_ERROR "OpenSSL library not found")
endif(NOT OPENSSL_FOUND)
target_include_directories(osslsigncode PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(osslsigncode PRIVATE ${OPENSSL_LIBRARIES})

# set cURL includes/libraries
if(CURL_FOUND)
  target_compile_definitions(osslsigncode PRIVATE ENABLE_CURL=1)
  target_include_directories(osslsigncode PRIVATE ${CURL_INCLUDE_DIRS})
  target_link_libraries(osslsigncode PRIVATE ${CURL_LIBRARIES})
  message(NOTICE "cURL support enabled")
else(CURL_FOUND)
  message(WARNING "cURL support disabled (library not found)")
endif(CURL_FOUND)

# add paths to linker search and installed rpath
set_target_properties(osslsigncode PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)

if(NOT WIN32) # temporarily disable malfunctioning features

if(WIN32)
  # set output directory
  set_target_properties(osslsigncode PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${PROJECT_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${PROJECT_BINARY_DIR}
  )
  # copy the libraries
  file(COPY ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES} DESTINATION ${PROJECT_BINARY_DIR})
endif(WIN32)

include(CMakeTest)

include(CMakeInstall)

if(NOT WIN32)
  include(CMakeDist)
endif(NOT WIN32)

endif(NOT WIN32) # temporarily disable malfunctioning features
