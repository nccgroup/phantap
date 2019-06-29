cmake_minimum_required(VERSION 2.6)

PROJECT(phantap C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

ADD_EXECUTABLE(phantap-learn phantap-learn.c)
TARGET_LINK_LIBRARIES(phantap-learn pcap)
INSTALL(TARGETS phantap-learn
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
