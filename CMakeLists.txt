cmake_minimum_required(VERSION 3.10)

# Set the project name
project(DNSServer)

include(FetchContent)

FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG yaml-cpp-0.7.0 # You can specify a tag, commit hash, or branch name
)
FetchContent_MakeAvailable(yaml-cpp)

# Add the cmake directory to the module path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

# Find the pcap library
find_package(Pcap REQUIRED)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(dns_server server.cpp)

# Link YAML-CPP and pcap with the executable
target_link_libraries(dns_server yaml-cpp ${PCAP_LIBRARIES})
include_directories(${PCAP_INCLUDE_DIRS})

