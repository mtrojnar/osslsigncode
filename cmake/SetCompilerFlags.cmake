include(CheckCCompilerFlag)

set(CMAKE_REQUIRED_QUIET ON)

function(add_debug_flag_if_supported flagname targets)
  check_c_compiler_flag("${flagname}" HAVE_FLAG_${flagname})
  if (HAVE_FLAG_${flagname})
    foreach(target ${targets})
      target_compile_options(${target} PRIVATE $<$<CONFIG:DEBUG>:${flagname}>)
    endforeach()
  endif()
endfunction()

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
    "-Wunused-function"
  )
  foreach(flag ${CHECKED_DEBUG_FLAGS})
    add_debug_flag_if_supported(${flag} ${targets})
  endforeach()
endfunction()

function(add_compile_flags target)
  if(MSVC)
    # Enable parallel builds
    target_compile_options(${target} PRIVATE /MP)
    # Use address space layout randomization, generate PIE code for ASLR (default on)
    target_link_options(${target} PRIVATE /DYNAMICBASE)
    # Create terminal server aware application (default on)
    target_link_options(${target} PRIVATE /TSAWARE)
    # Mark the binary as compatible with Intel Control-flow Enforcement Technology (CET) Shadow Stack
    target_link_options(${target} PRIVATE /CETCOMPAT)
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
    else()
      # Can handle addresses larger than 2 gigabytes
      target_link_options(${target} PRIVATE /LARGEADDRESSAWARE)
      # Safe structured exception handlers (x86 only)
      target_link_options(${target} PRIVATE /SAFESEH)
    endif()
    target_compile_options(${target} PRIVATE $<$<CONFIG:DEBUG>:/D_FORTIFY_SOURCE=2>)
    # Unrecognized compiler options are errors
    target_compile_options(${target} PRIVATE $<$<CONFIG:DEBUG>:/options:strict>)
  else(MSVC)
    check_c_compiler_flag("-fstack-protector-all"  HAVE_STACK_PROTECTOR_ALL)
    if(HAVE_STACK_PROTECTOR_ALL)
      target_link_options(${target} PRIVATE -fstack-protector-all)
    else()
      check_c_compiler_flag("-fstack-protector"    HAVE_STACK_PROTECTOR)
      if(HAVE_STACK_PROTECTOR)
        target_link_options(${target} PRIVATE -fstack-protector)
      else()
        message(WARNING "No stack protection supported")
      endif()
    endif()
    # Support address space layout randomization (ASLR)
    if(NOT (MINGW OR CYGWIN OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang"))
      target_compile_options(${target} PRIVATE -fPIE)
      target_link_options(${target} PRIVATE -fPIE -pie)
      target_link_options(${target} PRIVATE -Wl,-z,relro)
      target_link_options(${target} PRIVATE -Wl,-z,now)
      target_link_options(${target} PRIVATE -Wl,-z,noexecstack)
    endif(NOT (MINGW OR CYGWIN OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang"))
    target_link_options(${target} PRIVATE -fstack-check)
    add_compile_flag_to_targets(${target})
  endif(MSVC)
endfunction()

add_compile_flags(osslsigncode)
