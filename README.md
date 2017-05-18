GeoIP plugin for DNSCrypt
=========================

This is a [dnscrypt](https://dnscrypt.org) plugin to return a `REFUSED`
response code to DNS queries resolving to a given set of countries.

Dependencies
------------

- cmake
- GeoIP
- ldns

Installation
------------

```bash
$ mkdir build && cd build && cmake .. && make
```

The resulting plugin can be copied anywhere on the system.

Example usage
-------------

The full path to GeoIP's `GeoIP.dat` file must be provided, as well as
the path to a text file containing the set of country codes to block.
This text file should list one country per line. For example:

    CA
    UK

The plugin can then be loaded like any regular dnscrypt plugin, such as:

```bash
$ sudo dnscrypt-proxy --plugin libgeoip_block,--blacklist=/etc/blk-countries,--geoipdb=/etc/GeoIP.dat
```
