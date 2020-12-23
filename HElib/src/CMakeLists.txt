file(GLOB HELIB_SRC_FILES RELATIVE "${PROJECT_SOURCE_DIR}/src" "*.cpp")
file(GLOB HELIB_HDR_FILES RELATIVE "${PROJECT_SOURCE_DIR}/src" "*.h")

## Remove test files from the source file list.
foreach(prg ${TEST_FILES})
    list(FILTER HELIB_SRC_FILES EXCLUDE REGEX ${prg})
endforeach(prg)

if (BUILD_SHARED)
    add_library(fhe SHARED ${HELIB_SRC_FILES} ${HELIB_HDR_FILES})
else (BUILD_SHARED)
    add_library(fhe STATIC ${HELIB_SRC_FILES} ${HELIB_HDR_FILES})
endif (BUILD_SHARED)

if (ENABLE_DEBUG)
    target_compile_definitions(fhe PRIVATE DEBUG_PRINTOUT=1)
endif(ENABLE_DEBUG)

if (BUILD_AES)
    include_directories("${PROJECT_SOURCE_DIR}/src")
    add_subdirectory(aes)
endif(BUILD_AES)

if (ENABLE_TEST)
    add_subdirectory(test)
endif(ENABLE_TEST)
