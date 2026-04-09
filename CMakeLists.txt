cmake_minimum_required(VERSION 3.16)
project(nx2elf LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(nx2elf
    nx2elf.cpp
    elf_eh.cpp
    lz4.c
)
