cmake_minimum_required(VERSION 3.10)
project(escher_plugin C)

# Set your local path to the Wireshark source code here:
set(WIRESHARK_SRC_DIR "/Users/tcraven/dev/git/wireshark" CACHE PATH "Path to Wireshark source code")

# Find Wireshark standard includes and libraries
find_package(PkgConfig)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
pkg_check_modules(WIRESHARK REQUIRED wireshark)

# Setup include directories
include_directories(
    ${WIRESHARK_SRC_DIR}
    ${WIRESHARK_INCLUDE_DIRS}
    ${GLIB2_INCLUDE_DIRS}
)

# Define the library output
add_library(escher MODULE packet-escher.c)

# Configure compiler properties specific to Wireshark plugin requirements
set_target_properties(escher PROPERTIES 
    PREFIX "" 
    SUFFIX ".so" # Windows CMake will automatically change this to .dll
    C_STANDARD 99
)

# Link against standard Wireshark libs
target_link_libraries(escher 
    ${GLIB2_LIBRARIES}
    ${WIRESHARK_LIBRARIES}
)

# Install location (adjust standard paths based on OS)
if(WIN32)
    install(TARGETS escher DESTINATION "$ENV{APPDATA}/Wireshark/plugins")
else()
    install(TARGETS escher DESTINATION "$ENV{HOME}/.local/lib/wireshark/plugins")
endif()