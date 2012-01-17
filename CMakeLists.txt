cmake_minimum_required(VERSION 2.0)
project(Crc32bench)
set(CMAKE_BUILD_TYPE Release)
add_executable(bench bench.c bulk_crc32.c)
