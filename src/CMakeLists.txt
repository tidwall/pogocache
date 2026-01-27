###########
# Library #
###########

set(LIBRARY_NAME "lib${PROJECT_NAME}")

set(Header_Files
        "args.h"
        "buf.h"
        "cmds.h"
        "conn.h"
        "hashmap.h"
        "helppage.h"
        "lz4.h"
        "net.h"
        "openssl.h"
        "parse.h"
        "pogocache.h"
        "postgres.h"
        "save.h"
        "stats.h"
        "sys.h"
        "tls.h"
        "uring.h"
        "util.h"
        "xmalloc.h"
)
source_group("Header Files" FILES "${Header_Files}")

set(Source_Files
        "args.c"
        "buf.c"
        "cmds.c"
        "conn.c"
        "hashmap.c"
        "http.c"
        "lz4.c"
        "memcache.c"
        "net.c"
        "parse.c"
        "pogocache.c"
        "postgres.c"
        "resp.c"
        "save.c"
        "stats.c"
        "sys.c"
        "tls.c"
        "uring.c"
        "util.c"
        "xmalloc.c"
)
source_group("Source Files" FILES "${Source_Files}")

add_library("${LIBRARY_NAME}" "${Header_Files}" "${Source_Files}")

set(gitinfo "${CMAKE_CURRENT_BINARY_DIR}/gitinfo.h")
#if (NOT EXISTS "${gitinfo}")
execute_process(COMMAND git rev-parse --short HEAD OUTPUT_VARIABLE GIT_HASH OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND git describe --tags OUTPUT_VARIABLE GITVERS OUTPUT_STRIP_TRAILING_WHITESPACE)
configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/gitinfo.h.in"
        "${gitinfo}"
        @ONLY
)
#endif (NOT EXISTS "${gitinfo}")

include(GenerateExportHeader)
set(_export_file "${CMAKE_CURRENT_BINARY_DIR}/${LIBRARY_NAME}_export.h")
generate_export_header("${LIBRARY_NAME}" EXPORT_FILE_NAME "${_export_file}")

include(GNUInstallDirs)
target_include_directories(
        "${LIBRARY_NAME}"
        PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>"
        "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>"
        "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_link_libraries(
        "${LIBRARY_NAME}"
        PRIVATE
        "${PROJECT_NAME}_compiler_flags"
)
if (NOT NOOPENSSL)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(
            "${LIBRARY_NAME}"
            PRIVATE
            OpenSSL::SSL
    )
endif (NOT NOOPENSSL)

set_target_properties("${LIBRARY_NAME}" PROPERTIES LINKER_LANGUAGE C)

#######
# CLI #
#######

set(EXEC_NAME "${PROJECT_NAME}")

set(Exec_Source_Files "main.c")
source_group("${EXEC_NAME} Source Files" FILES "${Exec_Source_Files}")

add_executable("${EXEC_NAME}" "${Exec_Source_Files}")

target_link_libraries("${EXEC_NAME}" PRIVATE "${LIBRARY_NAME}")
set_target_properties("${EXEC_NAME}" PROPERTIES LINKER_LANGUAGE C)

#################
# Install rules #
#################

include(GNUInstallDirs)

# setup the version numbering
set_property(TARGET "${LIBRARY_NAME}" PROPERTY VERSION "${${PROJECT_NAME}_VERSION}")
set_property(TARGET "${LIBRARY_NAME}" PROPERTY SOVERSION "${${PROJECT_NAME}_VERSION_MAJOR}")

set(installable_libs # "${EXEC_NAME}"
        "${LIBRARY_NAME}")
if (TARGET "${DEPENDANT_LIBRARY}")
    list(APPEND installable_libs "${DEPENDANT_LIBRARY}")
endif ()
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.13")
    list(APPEND installable_libs "${PROJECT_NAME}_compiler_flags")
endif ()
install(TARGETS ${installable_libs}
        EXPORT "${LIBRARY_NAME}Targets"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(EXPORT "${LIBRARY_NAME}Targets" DESTINATION "${CMAKE_INSTALL_DATADIR}/${LIBRARY_NAME}")

install(FILES ${Header_Files} "${_export_file}" "${gitinfo}"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
