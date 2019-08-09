# Copyright (C) 2019 Deltik
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

project(mod_antiloris)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")

include_directories("${PROJECT_SOURCE_DIR}/lib/check")
add_subdirectory("${PROJECT_SOURCE_DIR}/lib/check")

include_directories("${PROJECT_SOURCE_DIR}/lib/croaring/include/roaring")
add_subdirectory("${PROJECT_SOURCE_DIR}/lib/croaring")
set(ROARING_BUILD_STATIC ON CACHE BOOL "Build a static library" FORCE)

find_program(APXS apxs)
if (NOT APXS)
    message(SEND_ERROR "Binary apxs is required but cannot be found. "
            "Install Apache HTTP Server development tools to resolve.")
else (NOT APXS)
    execute_process(COMMAND ${APXS} -q CFLAGS
            OUTPUT_VARIABLE APXS_C_FLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APXS} -q INCLUDEDIR
            OUTPUT_VARIABLE APXS_INCLUDEDIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${APXS_C_FLAGS} -I${APXS_INCLUDEDIR}")
    execute_process(COMMAND ${APXS} -q LDFLAGS
            OUTPUT_VARIABLE APXS_LDFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${APXS_LDFLAGS}")
    execute_process(COMMAND ${APXS} -q LIBEXECDIR
            OUTPUT_VARIABLE APXS_LIBEXECDIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(APACHE_MODULE_DIR "${APXS_LIBEXECDIR}" CACHE PATH
            "Installation directory for Apache modules")
endif (NOT APXS)

find_program(APR apr-config)
if (NOT APR)
    message(SEND_ERROR "Binary apr-config is required but cannot be found. "
            "Install the Apache HTTP Server development tools to resolve.")
else (NOT APR)
    execute_process(COMMAND ${APR} --cflags
            OUTPUT_VARIABLE APR_C_FLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${APR} --includedir
            OUTPUT_VARIABLE APR_INCLUDEDIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${APR_C_FLAGS} -I${APR_INCLUDEDIR}")
endif (NOT APR)

add_library(ip_helper STATIC ip_helper.c)
target_link_libraries(ip_helper roaring apr-1)
set_property(TARGET ip_helper PROPERTY POSITION_INDEPENDENT_CODE ON)

add_library(mod_antiloris MODULE mod_antiloris.c)
set_target_properties(mod_antiloris PROPERTIES PREFIX "")
target_link_libraries(mod_antiloris roaring apr-1 ip_helper)

add_executable(check_ip_helper check_ip_helper.c ip_helper.h ip_helper.c)
target_link_libraries(check_ip_helper check roaring apr-1)

enable_testing()
add_test(NAME check_ip_helper COMMAND check_ip_helper)