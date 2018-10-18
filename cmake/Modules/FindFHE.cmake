# - Try to find HElib (libfhe)
# Once done, this will define
#
#  FHE_FOUND - system has HElib
#  FHE_INCLUDE_DIRS - the HElib include directories
#  FHE_LIBRARIES - link these to use HElib

include(LibFindMacros)

# Dependencies
libfind_package(FHE GMP)
libfind_package(FHE NTL)

# Use pkg-config to get hints about paths
libfind_pkg_check_modules(FHE_PKGCONF HElib)

# Include dir
find_path(FHE_INCLUDE_DIR
        NAMES fhe.h
        PATHS ${FHE_PKGCONF_INCLUDE_DIRS}
        )

# Finally the library itself
find_library(FHE_LIBRARY
        NAMES fhe
        PATHS ${FHE_PKGCONF_LIBRARY_DIRS}
        )

# Set the include dir variables and the libraries and let libfind_process do the rest.
set(FHE_INCLUDE_DIR GMP_INCLUDE_DIR NTL_INCLUDE_DIR)
set(FHE_LIBRARY)
libfind_process(FHE)