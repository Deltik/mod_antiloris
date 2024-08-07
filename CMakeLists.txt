# Copyright (C) 2019-2024 Deltik <https://www.deltik.net/>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.5)

project(mod_antiloris C)

find_path(CHECK_INCLUDE_DIR check.c "${PROJECT_SOURCE_DIR}/lib/check/src")
if ((NOT CHECK_INCLUDE_DIR) OR (NOT EXISTS ${CHECK_INCLUDE_DIR}))
    message("Dependency libcheck was not found. Downloading from Git…")
    execute_process(COMMAND git submodule update --init -- lib/check
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endif ((NOT CHECK_INCLUDE_DIR) OR (NOT EXISTS ${CHECK_INCLUDE_DIR}))

include_directories("${PROJECT_SOURCE_DIR}/lib/check")
add_subdirectory("${PROJECT_SOURCE_DIR}/lib/check")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -s")

find_program(APXS apxs)
if (NOT APXS)
    message(SEND_ERROR "Binary apxs is required but cannot be found. "
            "Install Apache HTTP Server development tools to resolve.")
else (NOT APXS)
    execute_process(COMMAND ${APXS} -q CFLAGS
            OUTPUT_VARIABLE APXS_C_FLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APXS} -q INCLUDEDIR
            OUTPUT_VARIABLE APXS_INCLUDEDIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APXS} -q APR_INCLUDEDIR
            OUTPUT_VARIABLE APXS_APR_INCLUDEDIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APXS} -q EXTRA_INCLUDES
            OUTPUT_VARIABLE APXS_EXTRA_INCLUDES OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${APXS_C_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${APXS_INCLUDEDIR}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${APXS_APR_INCLUDEDIR}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${APXS_EXTRA_INCLUDES}")

    execute_process(COMMAND ${APXS} -q APR_CONFIG
            OUTPUT_VARIABLE APXS_APR_CONFIG OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APXS_APR_CONFIG} --link-libtool
            OUTPUT_VARIABLE APR_LINK_LIBTOOL OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(STRIP "${APR_LINK_LIBTOOL}" APR_LINK_LIBTOOL)
    string(REGEX REPLACE "\\/[^\\/]*$" "" APR_LINK_FIND_PATH "${APR_LINK_LIBTOOL}")
    find_library(APR_1_PATH apr-1 "${APR_LINK_FIND_PATH}")

    execute_process(COMMAND ${APXS} -q LDFLAGS
            OUTPUT_VARIABLE APXS_LDFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${APXS_LDFLAGS}")
    execute_process(COMMAND ${APXS} -q LIBEXECDIR
            OUTPUT_VARIABLE APXS_LIBEXECDIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(APACHE_MODULE_DIR "${APXS_LIBEXECDIR}" CACHE PATH
            "Installation directory for Apache modules")
endif (NOT APXS)

set (CMAKE_C_STANDARD 99)

add_library(mod_antiloris MODULE mod_antiloris.c ip_helper.c)
set_target_properties(mod_antiloris PROPERTIES PREFIX "")
target_link_libraries(mod_antiloris "${APR_1_PATH}")

if (CMAKE_BUILD_TYPE STREQUAL Release)
    add_custom_command(TARGET mod_antiloris POST_BUILD COMMAND strip -s mod_antiloris.so)
endif (CMAKE_BUILD_TYPE STREQUAL Release)

add_executable(check_ip_helper check_ip_helper.c ip_helper.h ip_helper.c)
target_link_libraries(check_ip_helper check "${APR_1_PATH}")

enable_testing()
add_test(NAME check_ip_helper COMMAND check_ip_helper)