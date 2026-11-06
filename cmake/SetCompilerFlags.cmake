include(CheckCCompilerFlag)

set(CMAKE_REQUIRED_QUIET ON)

option(OSSLSIGNCODE_STATIC_PIE "Build a fully static PIE executable (Linux only)" OFF)
if(OSSLSIGNCODE_STATIC_PIE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "OSSLSIGNCODE_STATIC_PIE is only supported on Linux")
endif()

function(add_debug_flag_if_supported flagname targets)
    check_c_compiler_flag("${flagname}" HAVE_FLAG_${flagname})
    if (HAVE_FLAG_${flagname})
        foreach(target ${targets})
            target_compile_options(${target} PRIVATE $<$<CONFIG:DEBUG>:${flagname}>)
        endforeach(target ${targets})
    endif(HAVE_FLAG_${flagname})
endfunction(add_debug_flag_if_supported flagname targets)

function(add_compile_flag_to_targets targets)
    set(CHECKED_DEBUG_FLAGS
        "-ggdb"
        "-g"
        "-O2"
        "-pedantic"
        "-Wall"
        "-Wextra"
        "-Wno-long-long"
        "-Wconversion"
        "-D_FORTIFY_SOURCE=2"
        "-Wformat=2"
        "-Wredundant-decls"
        "-Wcast-qual"
        "-Wnull-dereference"
        "-Wno-deprecated-declarations"
        "-Wmissing-declarations"
        "-Wmissing-prototypes"
        "-Wmissing-noreturn"
        "-Wmissing-braces"
        "-Wparentheses"
        "-Wstrict-aliasing=3"
        "-Wstrict-overflow=2"
        "-Wlogical-op"
        "-Wwrite-strings"
        "-Wcast-align=strict"
        "-Wdisabled-optimization"
        "-Wshift-overflow=2"
        "-Wundef"
        "-Wshadow"
        "-Wmisleading-indentation"
        "-Wabsolute-value"
        "-Wunused-parameter"
        "-Wunused-function")
    foreach(flag ${CHECKED_DEBUG_FLAGS})
        add_debug_flag_if_supported(${flag} ${targets})
    endforeach(flag ${CHECKED_DEBUG_FLAGS})
endfunction(add_compile_flag_to_targets targets)

function(add_compile_flags target)
    if(MSVC)
        # Enable parallel builds
        target_compile_options(${target} PRIVATE /MP)
        # Use address space layout randomization, generate PIE code for ASLR (default on)
        target_link_options(${target} PRIVATE /DYNAMICBASE)
        # Create terminal server aware application (default on)
        target_link_options(${target} PRIVATE /TSAWARE)
        # Mark the binary as compatible with Intel Control-flow Enforcement Technology (CET) Shadow Stack
        # /CETCOMPAT is only valid for x86/x64 targets; it errors with LNK1246 on ARM/ARM64.
        if(MSVC_C_ARCHITECTURE_ID MATCHES "^(X86|x64|AMD64)$")
            target_link_options(${target} PRIVATE /CETCOMPAT)
        endif()
        # Enable compiler generation of Control Flow Guard security checks
        target_compile_options(${target} PRIVATE /guard:cf)
        target_link_options(${target} PRIVATE /guard:cf)
        # Buffer Security Check
        target_compile_options(${target} PRIVATE /GS)
        # Suppress startup banner
        target_link_options(${target} PRIVATE /NOLOGO)
        # Generate debug info
        target_link_options(${target} PRIVATE /DEBUG)
        if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
            # High entropy ASLR for 64 bits targets (default on)
            target_link_options(${target} PRIVATE /HIGHENTROPYVA)
            # Enable generation of EH Continuation (EHCONT) metadata by the compiler
            #target_compile_options(${target} PRIVATE /guard:ehcont)
            #target_link_options(${target} PRIVATE /guard:ehcont)
        else("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
            # Can handle addresses larger than 2 gigabytes
            target_link_options(${target} PRIVATE /LARGEADDRESSAWARE)
            # Safe structured exception handlers (x86 only)
            target_link_options(${target} PRIVATE /SAFESEH)
        endif("${CMAKE_SIZEOF_VOID_P}" STREQUAL "8")
        target_compile_options(${target} PRIVATE $<$<CONFIG:DEBUG>:/D_FORTIFY_SOURCE=2>)
        # Unrecognized compiler options are errors
        target_compile_options(${target} PRIVATE $<$<CONFIG:DEBUG>:/options:strict>)
    else(MSVC)
        check_c_compiler_flag("-fstack-protector-all" HAVE_STACK_PROTECTOR_ALL)
        if(HAVE_STACK_PROTECTOR_ALL)
            target_link_options(${target} PRIVATE -fstack-protector-all)
        else(HAVE_STACK_PROTECTOR_ALL)
            check_c_compiler_flag("-fstack-protector" HAVE_STACK_PROTECTOR)
            if(HAVE_STACK_PROTECTOR)
                target_link_options(${target} PRIVATE -fstack-protector)
            else(HAVE_STACK_PROTECTOR)
                message(WARNING "No stack protection supported")
            endif(HAVE_STACK_PROTECTOR)
        endif(HAVE_STACK_PROTECTOR_ALL)
        # Support address space layout randomization (ASLR) / PIE
        if(UNIX AND NOT APPLE AND NOT CYGWIN)
            target_compile_options(${target} PRIVATE -fPIE)
            if(OSSLSIGNCODE_STATIC_PIE)
                check_c_compiler_flag("-static-pie" HAVE_STATIC_PIE)
                if(NOT HAVE_STATIC_PIE)
                    message(FATAL_ERROR "The compiler does not support -static-pie")
                endif()
                target_link_options(${target} PRIVATE -static-pie)
            else()
                target_link_options(${target} PRIVATE -pie)
            endif()
            target_link_options(${target} PRIVATE -fPIE -Wl,-z,relro,-z,now,-z,noexecstack)
        endif(UNIX AND NOT APPLE AND NOT CYGWIN)
        target_link_options(${target} PRIVATE -fstack-check)
        add_compile_flag_to_targets(${target})
    endif(MSVC)
endfunction(add_compile_flags target)

add_compile_flags(osslsigncode)

#[[
Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
]]
