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

# make find modules in cmake dir available
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")

# load CMake project modules
include(SetOptions)
include(FindOpenssl)
include(FindCurl)
include(FindMapping)

# use config.h
target_compile_definitions(osslsigncode PRIVATE HAVE_CONFIG_H=1)
configure_file(Config.h.in config.h)

# add include directories to osslsigncode
target_include_directories(osslsigncode PUBLIC "${PROJECT_BINARY_DIR}")

if(MSVC)
  # set output directory
  set_target_properties(osslsigncode PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${PROJECT_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${PROJECT_BINARY_DIR}
  )
  # copy necessary libraries
  file(COPY ${OPENSSL_LIBS} ${CURL_LIB} DESTINATION ${PROJECT_BINARY_DIR})
else()
  # set LD_LIBRARY_PATH
  set_target_properties(osslsigncode PROPERTIES
    INSTALL_RPATH_USE_LINK_PATH TRUE
  )
endif()

include(CMakeTest)
include(CMakeInstall)
if(NOT MSVC)
  include(CMakeDist)
endif()
