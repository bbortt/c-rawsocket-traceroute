`traceroute` implementation in C
===

## Usage
Compile using `make`.  Usage:
```shell
./traceroute [DOMAIN] [?INTERFACE]
```

## Example
```shell
$: ./traceroute google.com enp0s3
using networking interface enp0s3
will fire from networking interface 10.0.2.15
tracing down 'google.com' on '172.217.22.238'..
hop 1 - [_gateway]: 10.0.2.2
hop 2 - [10.7.0.1]: 10.7.0.1
[...]
hop 12 - [muc11s02-in-f14.1e100.net]: 172.217.22.238
trace completed!
```

## CRC implementation 
The file `crc.c` is part of GNUnet. \
Copyright (C) 2001, 2002, 2003, 2004, 2006 GNUnet e.V.

## License
This project is licensed under the terms of the [Apache 2.0 License](https://github.com/bbortt/c-rawsocket-traceroute/blob/master/LICENSE).
