# add command line options

# set Release build mode
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose Release or Debug" FORCE)
endif()

option(enable-strict "Enable strict compile mode" OFF)
option(enable-pedantic "Enable pedantic compile mode" OFF)
option(with-curl "Enable curl" ON)

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
