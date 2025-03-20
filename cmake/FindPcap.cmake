# in order to find the pcap library, CMake will look for the pcap.h header 
# file and the pcap library in the system's default include and library paths. 
# If they are found, it will set the PCAP_FOUND variable to TRUE and populate the 
# PCAP_LIBRARIES and PCAP_INCLUDE_DIRS variables with the appropriate paths. 
# If not found, PCAP_FOUND will be set to FALSE.
# the main CMakeLists.txt file includes the cmake directory to the module path
# and then calls find_package(Pcap REQUIRED) to find the pcap library.
# This will trigger the execution of the FindPcap.cmake script.

# this was the best way I could figure out to get the pcap library to be found for my 
# laptop and the lab machines

find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    set(PCAP_FOUND TRUE)
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
    set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
else()
    set(PCAP_FOUND FALSE)
endif()

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)
