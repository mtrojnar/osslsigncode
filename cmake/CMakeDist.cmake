# make dist
# cmake --build . --target package_source

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "OpenSSL based Authenticode signing for PE, CAB, CAT, MSI, APPX and script files")
set(CPACK_PACKAGE_INSTALL_DIRECTORY ${CPACK_PACKAGE_NAME})
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING.txt")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_SOURCE_GENERATOR "TGZ")
# Keep repository metadata, local experiments and generated files out of releases.
set(CPACK_SOURCE_IGNORE_FILES
    "/[.](git|github|pi|vs|vscode)(/|$)"
    "/[.]gitignore$"
    "/(CMakeFiles|Testing|_CPack_Packages)/"
    "/CMakeCache[.]txt$"
    "/CPack(Config|SourceConfig)[.]cmake$"
    "/CTestTestfile[.]cmake$"
    "/cmake_(install|uninstall)[.]cmake$"
    "/config[.]h$"
    "/install_manifest[.]txt$"
    "/stamp-h1$"
    "/(build[.]ninja|rules[.]ninja|compile_commands[.]json)$"
    "/[.]ninja_(deps|log)$"
    "/__pycache__/"
    "/misc/softhsm-example-token/(config[.]py|openssl[.]conf)$"
    "/misc/softhsm-example-token/(test|softhsm)[.][^/]*(/|$)"
    "[.](log|pyc|pyo|orig|rej|bak)$"
    "~$")

# Anchor source-root exclusions so example Makefiles remain in the archive.
list(APPEND CPACK_SOURCE_IGNORE_FILES
    "${PROJECT_SOURCE_DIR}/(build[^/]*|fuzz[^/]*)/"
    "${PROJECT_SOURCE_DIR}/Makefile$"
    "${PROJECT_SOURCE_DIR}/osslsigncode([.]exe|[.]1|[.]html)?$"
    "${PROJECT_SOURCE_DIR}/osslsigncode-[^/]+[.](tar[.](gz|bz2|xz)|zip)([.](asc|sig))?$")

include(CPack)
add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)

#[[
Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
]]
