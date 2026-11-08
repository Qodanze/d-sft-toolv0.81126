cmake_minimum_required(VERSION 3.16)
project(DSfTTool VERSION 0.2.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

# --- LD_PRELOAD sandbox/accounting shim (plain C) ---
add_library(dsftshim SHARED src/shim/shim.c)
target_compile_definitions(dsftshim PRIVATE _GNU_SOURCE)
set_target_properties(dsftshim PROPERTIES
    C_STANDARD 11
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# --- main GUI ---
add_executable(dsft-tool
    src/main.cpp
    src/mainwindow.cpp
    src/runner.cpp
    src/desktopentry.cpp
    src/selftest.cpp)
target_include_directories(dsft-tool PRIVATE src)
target_compile_options(dsft-tool PRIVATE -Wall -Wextra)
target_link_libraries(dsft-tool PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network)
add_dependencies(dsft-tool dsftshim)

# --- test helper programs (used by --selftest and manual testing) ---
set(TD "${CMAKE_BINARY_DIR}/testdata")
file(MAKE_DIRECTORY "${TD}/bin" "${TD}/scripts" "${TD}/desktop")
foreach(t hello writer bypass orphan remover echoline quotachild massmkdir rameater cpueater mmeater)
    add_executable(td_${t} testdata/${t}.c)
    set_target_properties(td_${t} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${TD}/bin"
        OUTPUT_NAME ${t})
endforeach()
file(COPY testdata/scripts/ DESTINATION "${TD}/scripts")
file(COPY testdata/desktop/ DESTINATION "${TD}/desktop")
