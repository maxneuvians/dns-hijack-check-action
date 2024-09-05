# DNS hijack check action

This action takes a list of domain names through a file input and checks if they resolve properly or return NXDOMAIN for a DNS query. If the domain does not resolve it will check if there are any CNAMEs attached to the domain that can be used as part of a subdomain takeover. If the domain is vulnerable to subdomain takeover, it will be written to a file called `critical.json`. 

Domains that do resolve properly, but still contain a CNAME to a vulnerable service will be written to a file called `potential.json`.

Services that are considered vulnerable to subdomain takeover are listed in `fingerprints.go`.
