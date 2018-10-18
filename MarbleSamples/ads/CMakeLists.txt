cmake_minimum_required(VERSION 3.8)

set(CMAKE_CXX_STANDARD 14)

find_package(GMP REQUIRED)
find_package(NTL REQUIRED)


add_executable(MarbleSamples_Ads ads.cpp)
target_link_libraries(MarbleSamples_Ads Marble fhe ntl gmp m)
target_include_directories(MarbleSamples_Ads PUBLIC "../../Marble")
