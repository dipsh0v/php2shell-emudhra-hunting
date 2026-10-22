# php2shell and eMudhra hunting queries

KQL for Microsoft Defender XDR advanced hunting and Microsoft Sentinel, covering two
unrelated events from the week of 20 October 2026.

**php2shell**, CVE-2026-109618 and CVE-2026-109619, two unauthenticated remote code
execution flaws in PHP core, CVSS v4.0 9.2, fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35.
Exploitation attempts are confirmed from 17 October 2026. No successful compromise of a
production system has been confirmed by anyone.

**The eMudhra certificate authority key compromise**, in which private keys for eight
intermediate CAs were recovered, six for TLS and two for code signing. One of the
recovered private key values was the integer 4.

## Read this before you run anything

**No attacker indicators exist for php2shell.** No IP addresses, no domains, no file
hashes, no web shell names, no user agent strings, no request paths. Tenable, Huntress,
Recorded Future, SOC Prime and Abstract Security all state this in as many words. Every
php2shell query here is therefore behavioural or structural, and several of them would
fire on any web shell from any cause. That is a property of the available intelligence,
not a shortcut.

The single most specific php2shell indicator published anywhere is the string
`PHP_SESSION_UPLOAD_PROGRESS` in an HTTP POST body. It appears in exactly one production
signature, Corelight Suricata SID 3000650, and Corelight says plainly that a match does
not establish an exploit attempt. Most organisations do not log POST bodies at all. The
gap between those two facts is the honest summary of where detection stands today.

The eMudhra half is the opposite shape. The identifiers are published and precise, and
the problem is retention rather than specificity: the exposure window runs roughly
seventeen months, and Defender XDR advanced hunting holds thirty days.

## Files

| File | What is in it |
|---|---|
| `queries-defender-xdr.md` | Defender XDR advanced hunting queries, plus three pre-flight checks |
| `queries-sentinel.md` | Sentinel queries, including the request layer work that Defender tables cannot reach |
| `notes-caveats.md` | What was verified and what was not, the suggested order of work, design decisions |

Query IDs are shared across the three files. A covers exposure, B covers exploitation
attempts at the request layer, C covers post-exploitation on the host, D covers eMudhra.

## Related work

FalconForce published four hunts for the same two events in their FalconFriday repository:
[`hunts/php-cert-hunts.md`](https://github.com/FalconForceTeam/FalconFriday/blob/main/hunts/php-cert-hunts.md).
They are not reproduced here. D-D1, D-D2, C-D5 and A5 answer the same questions with an
independent implementation, and the design notes on each say where the approaches differ.

## How to use this

Start with the three pre-flight queries, P-1, P-2 and D-D0. They take about a minute
between them and they answer questions that this pack would otherwise have to leave as
assumptions about your tenant: which `ActionType` values your tables actually emit, which
tables carry data on which operating systems, and whether `SslConnectionInspected`
records the full certificate chain or only the leaf.

The suggested order after that is in `notes-caveats.md`.

Every query ships a working default wherever a value has to come from your environment,
with the placeholder name in a comment beside it. Paste and run first, tune second. Two
places have no sensible default and are commented out in line.

Each query states whether it is a detection candidate, meaning the volume is low enough
to alert on, or a hunt, meaning it needs a person to look at the output. Most are hunts.

## Status

Written 22 October 2026, against the published intelligence as it stood that day. The
affected PHP version lower bound is still disputed between sources, and the GHSA advisory
text could not be retrieved to settle it. `notes-caveats.md` lists that and everything
else that could not be verified. Nothing here has been run against a production tenant.
Every query was checked against Microsoft's public schema reference, not against live
data, so treat a first run as validation and report anything that does not parse.

## Contributing

Issues and pull requests are welcome, especially results from running the pre-flight
queries on Linux-heavy tenants, and a verified SHA-256 for the sixteenth eMudhra
certificate, which is deliberately left out until confirmed. See the identifier set in
`queries-defender-xdr.md`.

## Licence

Queries and notes in this repository are released under the MIT licence, see `LICENSE`.
