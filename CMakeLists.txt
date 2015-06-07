cmake_minimum_required(VERSION 2.8)

project(geoip-block C)

set(GEOIP_BLOCK_MAJOR_VERSION 0)
set(GEOIP_BLOCK_MINOR_VERSION 1)
set(GEOIP_BLOCK_VERSION ${GEOIP_BLOCK_MAJOR_VERSION}.${GEOIP_BLOCK_MINOR_VERSION})

set(INSTALL_LIB_DIR lib/dnscrypt-proxy CACHE PATH "Installation directory for libraries")

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)

find_library(GEOIP_LIBRARY NAMES GeoIP libGeoIP)
find_library(LDNS_LIBRARY NAMES ldns libldns)

add_library(geoip-block SHARED geoip-block.c)

target_link_libraries(geoip-block GeoIP ldns)

install(TARGETS geoip-block DESTINATION ${INSTALL_LIB_DIR})

