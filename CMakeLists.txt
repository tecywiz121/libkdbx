cmake_minimum_required(VERSION 2.8)
project(KDBX)

# Add cmake modules directory
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${KDBX_SOURCE_DIR}/cmake/Modules/")

find_package(CryptoPP REQUIRED)
include_directories(${CRYPTOPP_INCLUDE_DIR})

find_package(PugiXML REQUIRED)
include_directories(${PugiXML_INCLUDE_DIR})

set(CMAKE_CXX_FLAGS "-g3 -gdwarf-3 -Wall -Wextra -Werror -Wstrict-aliasing -std=c++11 -pedantic")

add_executable(kdbx src/kdbx.cpp src/hashbuf.cpp)
target_link_libraries(kdbx ${CRYPTOPP_LIBRARIES} ${PugiXML_LIBRARY})
