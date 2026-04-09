cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0091 NEW)
project(nx2elf LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(nx2elf
    nx2elf.cpp
    elf_eh.cpp
    lz4.c
)

set_property(TARGET nx2elf PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

install(TARGETS nx2elf)

set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_FILE_NAME "nx2elf-${CMAKE_SYSTEM_NAME}")
include(CPack)
