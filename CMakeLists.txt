cmake_minimum_required(VERSION 3.9)
project(wow_srp VERSION 0.0.1 DESCRIPTION "World of Warcraft SRP Library")

add_library(wow_srp SHARED SRP.cpp BigNum.cpp)
target_link_libraries(wow_srp ssl crypto)

set_target_properties(wow_srp PROPERTIES PUBLIC_HEADER SRP.h)
include(GNUInstallDirs)

install(FILES "BigNum.h" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wow_srp)

install(TARGETS wow_srp
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wow_srp)

configure_file(wow_srp.pc.in wow_srp.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/wow_srp.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)