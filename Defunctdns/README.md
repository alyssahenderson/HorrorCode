# defunctdns

Small UDP DNS server that returns A records from `records.txt` and intentionally mishandles AAAA to simulate a broken DNS setup (unless -fix flag is set).

## Usage

Run:

```bash
defunctdns -port 5353 -log
```

Flags:

- `-port` (default `53`): UDP port to listen on.
- `-soa`: include an SOA record in the authority section for AAAA queries that return NXDOMAIN.
- `-fix`: for existing names, return NOERROR with an empty answer (NODATA) on AAAA instead of NXDOMAIN.
- `-log`: log DNS requests to stdout.

## records.txt

The server loads records from `records.txt` in the working directory. Each line is:

```
name ip
```

Lines starting with `#` or comments after `#` are ignored. If the file is missing, the server creates it with a dummy record and example comments.

Example:

```
test.local 10.10.10.10
```

## Why AAAA NXDOMAIN is bad

Returning NXDOMAIN for an existing name that has an A record is an error because it claims the name does not exist at all. This can cause:

- Negative caching by resolvers, hiding the valid A record for the cache TTL.
- Happy Eyeballs and dual-stack clients to skip IPv4 fallback or mark the hostname as non-existent.
- Confusing behavior for apps and monitoring that treat NXDOMAIN as a permanent absence of the host.

If you want a correct “no AAAA” response for an existing name, use `-fix` to return NOERROR with an empty answer (NODATA) instead.
