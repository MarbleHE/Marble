cmake_minimum_required(VERSION 3.8)

set(CMAKE_CXX_STANDARD 14)

find_package(GMP REQUIRED)
find_package(NTL REQUIRED)

add_executable(MarbleSamples_hd_batched hd_batched.cpp)
target_link_libraries(MarbleSamples_hd_batched Marble fhe ntl gmp m)
target_include_directories(MarbleSamples_hd_batched PUBLIC "../../Marble")