# Security

## Trust model

`nmap-scan` is a local command-line tool that trusts its operator.
`--scan-args` is operator input. The argument validator rejects Nmap
output options so the wrapper keeps control of where XML goes, but it
is a local-operator guard, not a sandbox: it does not make arbitrary
arguments safe to accept from untrusted sources.

**Do not** expose `nmap-scan`, or its arguments, through a web
service, API, job queue, or any other interface that accepts input
from anyone other than the operator, without an allowlist in front of
it. If you wrap this tool, the allowlist — not this validator — is
your security boundary.

## Scan output is sensitive

Saved XML and reports can contain hostnames, service banners, and
script output from the scanned systems. Treat them as potentially
sensitive data: do not commit real scan results, do not paste them
into public issues, and do not share them beyond the people who need
to see them.

## Reporting a vulnerability

Report security issues privately through the repository's Security
tab (or, if that is unavailable, by contacting the maintainer
directly) rather than opening a public issue. Do not attach real scan
output to a security report unless it is needed to reproduce the
issue, and redact hostnames and addresses first where you can.
