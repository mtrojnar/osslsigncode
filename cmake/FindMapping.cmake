include(CheckIncludeFile)
include(CheckFunctionExists)

if(NOT MSVC)
  check_function_exists(getpass HAVE_GETPASS)
  check_include_file(termios.h HAVE_TERMIOS_H)
  check_include_file(sys/mman.h HAVE_SYS_MMAN_H)
  if(HAVE_SYS_MMAN_H)
    check_function_exists(mmap HAVE_MMAP)
    if(NOT HAVE_MMAP)
      message(FATAL_ERROR "Error: Need mmap to build.")
    endif()
  endif()
endif()

# include wincrypt.h in Windows.h
if(MSVC AND NOT CYGWIN)
  check_include_file(windows.h HAVE_MAPVIEWOFFILE)
  if(NOT (HAVE_MMAP OR HAVE_MAPVIEWOFFILE))
    message(FATAL_ERROR "Error: Need file mapping function to build.")
  endif()
endif()
