cmake_minimum_required(VERSION 2.6)

PROJECT(phantap C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

find_package(PkgConfig REQUIRED)
pkg_search_module(NL REQUIRED IMPORTED_TARGET libnl-tiny libnl-3.0)

ADD_EXECUTABLE(phantap-learn phantap-learn.c dhcp.c netlink.c)
TARGET_LINK_LIBRARIES(phantap-learn pcap PkgConfig::NL)
INSTALL(TARGETS phantap-learn
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
