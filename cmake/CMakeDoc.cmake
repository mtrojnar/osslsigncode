# documentation with Pandoc
# cmake --build .

find_program(PANDOC pandoc)

if(NOT PANDOC)
    message(WARNING "CMakeDoc: pandoc not found, documentation disabled")
    return()
endif(NOT PANDOC)

set(DOC_MD "${PROJECT_SOURCE_DIR}/osslsigncode.md")

if(NOT EXISTS "${DOC_MD}")
    message(WARNING "CMakeDoc: markdown source not found: ${DOC_MD}")
    return()
endif(NOT EXISTS "${DOC_MD}")

set(MAN_PAGE "${PROJECT_BINARY_DIR}/osslsigncode.1")
set(HTML_PAGE "${PROJECT_BINARY_DIR}/osslsigncode.html")

add_custom_command(
    OUTPUT "${MAN_PAGE}"
    COMMAND "${PANDOC}" -s "${DOC_MD}" -t man -o "${MAN_PAGE}"
    DEPENDS "${DOC_MD}"
    COMMENT "CMakeDoc: generating man page"
    VERBATIM)

add_custom_command(
    OUTPUT "${HTML_PAGE}"
    COMMAND "${PANDOC}" -s --toc --toc-depth=2 "${DOC_MD}" -t html -o "${HTML_PAGE}"
    DEPENDS "${DOC_MD}"
    COMMENT "CMakeDoc: generating HTML documentation"
    VERBATIM)

add_custom_target(docs ALL DEPENDS "${MAN_PAGE}" "${HTML_PAGE}")

#[[
Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
]]
