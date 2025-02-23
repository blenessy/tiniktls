# https://github.com/chaoticgd/ccc/blob/main/musl.cmake
# CMake toolchain file for building with a musl libc cross compiler on Linux.
# To use: cmake -B bin -DCMAKE_TOOLCHAIN_FILE=musl.cmake

set(CMAKE_SYSTEM_NAME "Linux")
set(CMAKE_SYSTEM_PROCESSOR "x86_64")

set(CMAKE_C_COMPILER "x86_64-alpine-linux-musl-gcc")
set(CMAKE_C_COMPILER_AR "x86_64-alpine-linux-musl-ar")
set(CMAKE_C_COMPILER_RANLIB "x86_64-alpine-linux-musl-ranlib")
set(CMAKE_CXX_COMPILER "x86_64-alpine-linux-musl-g++")
set(CMAKE_CXX_COMPILER_AR "x86_64-alpine-linux-musl-ar")
set(CMAKE_CXX_COMPILER_RANLIB "x86_64-alpine-linux-musl-ranlib")

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")
