# HorrorCode

Over the years I've created some code for demo / teaching new engineers about various IT concepts, e.g. performance, security, e.t.c

This repository contains a set of tools, that emulate horrible software / configuration or just coded poorly on purpose. For example:

- A dual-stack DNS server that returns A on IPv4 and NXDOMAIN on IPv6 (Defunctdns)
- A Windows Filter driver, that adds IO delay (CustomIOFilterDriver)
- A simple web server that sets RFC 6265-violating cookies (literal backslashes) to test how proxies/middleware handle non-compliant cookie values (Non-RFC-Compliant-Cookie)
- A windows driver, that causes a kernel panic (DPCBugcheckDriver)

Use the stuff here with caution, it is absolutely horrible **horrorcode**.
