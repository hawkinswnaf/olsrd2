#!/bin/cmake

# look for git executable 
set (found_git false)
find_program(found_git git)

SET(OONF_APP_GIT "cannot read git repository")

IF(NOT ${found_git} STREQUAL "found_git-NOTFOUND")
	# get git description WITH dirty flag
	execute_process(COMMAND git describe --always --long --tags --dirty --match "v[0-9]*"
		OUTPUT_VARIABLE OONF_APP_GIT_TAG OUTPUT_STRIP_TRAILING_WHITESPACE)
	STRING(REGEX REPLACE "^v(.*)-[^-]*-[^-]*$" "\\1" OONF_APP_GIT ${OONF_APP_GIT_TAG})
ENDIF()

# compare with version number
STRING(REGEX MATCH "${OONF_APP_VERSION}" FOUND_VERSION ${OONF_APP_GIT})
IF (NOT FOUND_VERSION)
	message (FATAL_ERROR "App version '${OONF_APP_VERSION}'"
		" is not present in git description '${OONF_APP_GIT}'."
		" Please re-run 'cmake ..' to update build files")
ENDIF (NOT FOUND_VERSION)

# create builddata file
configure_file (${SRC} ${DST})
