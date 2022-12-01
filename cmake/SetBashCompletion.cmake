# This list describes the default variables included in the bash-completion package:
# BASH_COMPLETION_VERSION "@VERSION@"
# BASH_COMPLETION_PREFIX "@prefix@"
# BASH_COMPLETION_COMPATDIR "@sysconfdir@/bash_completion.d"
# BASH_COMPLETION_COMPLETIONSDIR "@datadir@/@PACKAGE@/completions"
# BASH_COMPLETION_HELPERSDIR "@datadir@/@PACKAGE@/helpers"
# BASH_COMPLETION_FOUND "TRUE"
# https://github.com/scop/bash-completion/blob/master/bash-completion-config.cmake.in

if(NOT MSVC)
  if(BASH_COMPLETION_USER_DIR)
    set(BASH_COMPLETION_COMPLETIONSDIR "${BASH_COMPLETION_USER_DIR}/bash-completion/completions")
  else(BASH_COMPLETION_USER_DIR)
    find_package(bash-completion QUIET)
    if(NOT BASH_COMPLETION_FOUND)
      set(SHAREDIR "${CMAKE_INSTALL_PREFIX}/share")
      set(BASH_COMPLETION_COMPLETIONSDIR "${SHAREDIR}/bash-completion/completions")
    endif(NOT BASH_COMPLETION_FOUND)
  endif(BASH_COMPLETION_USER_DIR)

  message(STATUS "Using bash completions dir ${BASH_COMPLETION_COMPLETIONSDIR}")
  install(FILES "osslsigncode.bash" DESTINATION ${BASH_COMPLETION_COMPLETIONSDIR})
endif(NOT MSVC)
