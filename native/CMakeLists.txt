# Native side of Tessera.Nxpsc, built from the external/libnxpsc submodule.
#
#   nxpsc           libnxpsc's shared library (nxpsc.dll / libnxpsc.so / libnxpsc.dylib),
#                   what Tessera.Nxpsc P/Invokes
#   nxpsc_mockcard  libnxpsc's tests/mockcard.c behind a stateful shim, what
#                   Tessera.Nxpsc.MockCard P/Invokes
#   layout_probe    prints sizeof/offsetof of libnxpsc's public structs; the
#                   tests compare it with the managed mirrors
#
# Everything lands in <build>/out:
#   cmake -S native -B native/build -DCMAKE_BUILD_TYPE=Release
#   cmake --build native/build --config Release

cmake_minimum_required(VERSION 3.16)
project(tessera_nxpsc_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(LIBNXPSC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../external/libnxpsc" CACHE PATH "libnxpsc source")
get_filename_component(LIBNXPSC_DIR "${LIBNXPSC_DIR}" ABSOLUTE)
if(NOT EXISTS "${LIBNXPSC_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "libnxpsc not found at ${LIBNXPSC_DIR}; run: git submodule update --init")
endif()

# one flat output directory, also for multi-config generators
set(NXPSC_OUT "${CMAKE_BINARY_DIR}/out")
foreach(kind RUNTIME LIBRARY ARCHIVE)
    set(CMAKE_${kind}_OUTPUT_DIRECTORY "${NXPSC_OUT}")
    foreach(config Debug Release RelWithDebInfo MinSizeRel)
        string(TOUPPER ${config} CONFIG)
        set(CMAKE_${kind}_OUTPUT_DIRECTORY_${CONFIG} "${NXPSC_OUT}")
    endforeach()
endforeach()

set(NXPSC_BUILD_SHARED ON CACHE BOOL "" FORCE)
set(NXPSC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(NXPSC_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory("${LIBNXPSC_DIR}" libnxpsc)

add_library(nxpsc_mockcard SHARED
    nxpsc_mockcard.c
    "${LIBNXPSC_DIR}/tests/mockcard.c"
)
target_include_directories(nxpsc_mockcard PRIVATE
    "${LIBNXPSC_DIR}/tests"
    "${LIBNXPSC_DIR}/src"
    "${LIBNXPSC_DIR}/third_party"
)
# the mock carries its own static copy of libnxpsc for the card side crypto
target_link_libraries(nxpsc_mockcard PRIVATE nxpsc)
if(WIN32)
    target_link_libraries(nxpsc_mockcard PRIVATE bcrypt)
endif()
set_target_properties(nxpsc_mockcard PROPERTIES
    C_VISIBILITY_PRESET hidden
    PREFIX ""
    IMPORT_SUFFIX ".dll.lib"
)
# on ELF, keep the embedded static libnxpsc private and bound to itself, so it
# neither exports nxpsc_* next to the real libnxpsc.so nor resolves to it
if(UNIX AND NOT APPLE)
    target_link_options(nxpsc_mockcard PRIVATE "LINKER:--exclude-libs,ALL" "LINKER:-Bsymbolic")
endif()

add_executable(layout_probe layout_probe.c)
target_link_libraries(layout_probe PRIVATE nxpsc)
