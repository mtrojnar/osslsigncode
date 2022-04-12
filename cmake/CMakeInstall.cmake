# make install
# cmake --install . --prefix "/home/myuser/installdir"

# installation rules for a project
set(BINDIR "${CMAKE_INSTALL_PREFIX}/bin")
install(TARGETS osslsigncode RUNTIME DESTINATION ${BINDIR})
if(MSVC)
  install(FILES
    "${PROJECT_BINARY_DIR}/libcrypto-3-x64.dll"
    "${PROJECT_BINARY_DIR}/libssl-3-x64.dll"
    "${PROJECT_BINARY_DIR}/libcurl.dll"
    DESTINATION ${BINDIR}
  )
endif()

# install bash completion script
if(NOT MSVC)
  find_package(bash-completion QUIET)
  if(NOT BASH_COMPLETION_COMPLETIONSDIR)
    if(BASH_COMPLETION_COMPATDIR)
      set(BASH_COMPLETION_COMPLETIONSDIR ${BASH_COMPLETION_COMPATDIR})
    else()
      set(SHAREDIR "${CMAKE_INSTALL_PREFIX}/share")
      set(BASH_COMPLETION_COMPLETIONSDIR "${SHAREDIR}/bash-completion/completions")
    endif()
  endif()
  message(STATUS "Using bash completions dir ${BASH_COMPLETION_COMPLETIONSDIR}")
  install(FILES "osslsigncode.bash" DESTINATION ${BASH_COMPLETION_COMPLETIONSDIR})
endif()
