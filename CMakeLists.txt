cmake_minimum_required(VERSION 2.8)

project(geoip-block C)

set(GEOIP_BLOCK_MAJOR_VERSION 0)
set(GEOIP_BLOCK_MINOR_VERSION 1)
set(GEOIP_BLOCK_VERSION ${GEOIP_BLOCK_MAJOR_VERSION}.${GEOIP_BLOCK_MINOR_VERSION})

set(INSTALL_LIB_DIR lib/dnscrypt-proxy CACHE PATH "Installation directory for libraries")

find_library(GEOIP_LIBRARY NAMES GeoIP libGeoIP)
find_library(LDNS_LIBRARY NAMES ldns libldns)

add_library(geoip-block SHARED geoip-block.c)

target_link_libraries(geoip-block GeoIP ldns)

install(TARGETS geoip-block DESTINATION ${INSTALL_LIB_DIR})

