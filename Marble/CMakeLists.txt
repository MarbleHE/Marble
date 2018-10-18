cmake_minimum_required(VERSION 3.8)

set(CMAKE_CXX_STANDARD 14)

find_package(GMP REQUIRED)
find_package(NTL REQUIRED)

set(SOURCE_FILES
        M.h
        M.cpp
        M_HElib.cpp
        M_HElib.h
        M_HElibImpl.h
        M_HElibImpl.cpp
        timer.h
        timer.cpp
        BitHelpers.h
        BitHelpers.cpp)


add_library(Marble ${SOURCE_FILES})
target_include_directories(Marble PUBLIC "../HElib/src")
target_link_libraries(Marble fhe ntl gmp m)

if (ENABLE_DEBUG)
    target_compile_definitions(Marble PRIVATE DEBUG_PRINTOUT=1)
endif(ENABLE_DEBUG)