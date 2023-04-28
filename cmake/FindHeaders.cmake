include(CheckIncludeFile)
include(CheckFunctionExists)

if(UNIX)
    check_function_exists(getpass HAVE_GETPASS)
    check_include_file(termios.h HAVE_TERMIOS_H)
    check_include_file(sys/mman.h HAVE_SYS_MMAN_H)
    if(HAVE_SYS_MMAN_H)
        check_function_exists(mmap HAVE_MMAP)
    endif(HAVE_SYS_MMAN_H)
else(UNIX)
    check_include_file(windows.h HAVE_MAPVIEWOFFILE)
endif(UNIX)

if(NOT (HAVE_MMAP OR HAVE_MAPVIEWOFFILE))
    message(FATAL_ERROR "Error: Need file mapping function to build.")
endif(NOT (HAVE_MMAP OR HAVE_MAPVIEWOFFILE))

#[[
Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
]]
