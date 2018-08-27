cmake_minimum_required(VERSION 3.10)
project(monster_hunter)

set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(third_party)

set(SOURCE_FILES src/main.cc)

add_executable(monster_hunter_crypt ${SOURCE_FILES})
target_compile_options(monster_hunter_crypt PRIVATE -Wall -Wextra)
#target_include_directories(monster_hunter_crypt PRIVATE include/)
target_link_libraries(monster_hunter_crypt fmt GSL "-lgcrypt")

