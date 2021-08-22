cmake_minimum_required(VERSION 3.0)

PROJECT(phantap C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Wall -Werror --std=gnu99 -Wmissing-declarations)

if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "None")
    set (CMAKE_BUILD_TYPE "RelWithDebInfo")
    message (STATUS "CMAKE_BUILD_TYPE is not set, set to default = ${CMAKE_BUILD_TYPE}")
endif ()
message (STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")

find_package(PkgConfig REQUIRED)
pkg_search_module(NL REQUIRED IMPORTED_TARGET libnl-tiny libnl-3.0)

ADD_EXECUTABLE(phantap-learn phantap-learn.c dhcp.c netlink.c)
TARGET_LINK_LIBRARIES(phantap-learn pcap PkgConfig::NL)
INSTALL(TARGETS phantap-learn
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
