# php2shell and eMudhra: Defender XDR advanced hunting queries

Two unrelated October 2026 events, one query set. The php2shell material (CVE-2026-109618, CVE-2026-109619) is entirely behavioural and structural, because no attacker IOCs have been published by anyone: no IPs, no domains, no hashes, no web shell names, no request paths. If you see a query in this file that implies otherwise, it is wrong and you should delete it. The eMudhra material is retrospective and IOC-driven, because the certificate identifiers are published and precise.

Sentinel variants are in `queries-sentinel.md`. Verification caveats and the suggested order of work are in `notes-caveats.md`. Query IDs are shared across all three files.

Everything here was written against the public Microsoft schema reference. Every query parses as published: where a value has to come from your environment, the query ships a working default and the placeholder name sits in the comment beside it, so you can paste and run first and tune second. Two exceptions are marked in place, where no sensible default exists and the affected lines are commented out.

## Placeholders used in this file

Each one appears as a comment next to a working default, not inside the query expression.

| Placeholder | Appears in | Default shipped | What to put there |
|---|---|---|---|
| `<YOUR_WORKER_RESPAWN_BASELINE>` | B-D1 | `200` | Normal PHP or Apache child spawns per 5 minutes per host. Measure first. |
| `<YOUR_WEB_ROOT_PATH>` | C-D3 | `/var/www/` | Document root. Case-sensitive on Linux, so the query lowercases the comparison side. |
| `<YOUR_SESSION_SAVE_PATH>` | C-D3 | `/var/lib/php/sessions` | PHP `session.save_path`. |
| `<YOUR_KNOWN_GOOD_COMMANDLINE_FRAGMENT>` | C-D1, C-D5 | one inert string | Allow-list fragments for benign PHP child processes. The array must stay non-empty or `has_any` errors. |
| `<YOUR_PROXY_EGRESS_IPS>` | C-D4 | one inert string | Approved public egress addresses for the web tier. |

---

# Pre-flight checks

Three cheap queries that answer questions this pack would otherwise have to leave as caveats. Run all three before anything else. Each takes well under a minute.

Microsoft publishes no per-platform table coverage and no `ActionType` value lists outside the in-portal schema reference. That is not a reason to guess. It is a reason to measure in your own tenant, which is what P-1 and P-2 do.

## P-1. Enumerate the `ActionType` values each table actually produces

**Detection candidate or hunt:** neither, this is reconnaissance. **Needs:** the four `Device*` event tables. **Lookback:** 1 day. **Volume:** a few dozen rows. **Why it exists:** every `ActionType` filter in this pack depends on value names Microsoft does not publish in the online schema reference. This retires that caveat in one minute.

```kql
// Which ActionType values does this tenant actually produce, per table?
union
    (DeviceProcessEvents   | where Timestamp > ago(1d) | extend Tbl = "DeviceProcessEvents"),
    (DeviceNetworkEvents   | where Timestamp > ago(1d) | extend Tbl = "DeviceNetworkEvents"),
    (DeviceFileEvents      | where Timestamp > ago(1d) | extend Tbl = "DeviceFileEvents"),
    (DeviceImageLoadEvents | where Timestamp > ago(1d) | extend Tbl = "DeviceImageLoadEvents")
| summarize Events = count(), Devices = dcount(DeviceId) by Tbl, ActionType
| order by Tbl asc, Events desc
```

**Triage.** First, confirm `ProcessCreated`, `FileCreated`, `FileModified`, `FileRenamed`, `SslConnectionInspected`, `InboundConnectionAccepted` and `InboundInternetScanInspected` appear, because this pack filters on all seven. Second, note every value ending in `Inspected`, because C-D4 excludes that whole family by suffix. Third, if an expected value is absent, the query that depends on it will return nothing and you need to know that before you run it, not after.

## P-2. Which tables carry data on which platforms

**Detection candidate or hunt:** neither. **Needs:** `DeviceInfo` plus the event tables. **Lookback:** 1 day. **Volume:** one row per table and platform. **Why it exists:** PHP mostly runs on Linux, several Defender tables behave differently there, and Microsoft does not document which tables Linux populates. This is the only way to know.

```kql
// Table coverage by OS platform. A table and platform pair missing here is a blind spot.
let platforms =
    DeviceInfo
    | where Timestamp > ago(1d)
    | summarize arg_max(Timestamp, OSPlatform, OSDistribution) by DeviceId
    | project DeviceId, OSPlatform, OSDistribution;
union
    (DeviceProcessEvents    | where Timestamp > ago(1d) | extend Tbl = "DeviceProcessEvents"),
    (DeviceNetworkEvents    | where Timestamp > ago(1d) | extend Tbl = "DeviceNetworkEvents"),
    (DeviceFileEvents       | where Timestamp > ago(1d) | extend Tbl = "DeviceFileEvents"),
    (DeviceImageLoadEvents  | where Timestamp > ago(1d) | extend Tbl = "DeviceImageLoadEvents")
| summarize Events = count() by Tbl, DeviceId
| join kind=inner platforms on DeviceId
| summarize Devices = dcount(DeviceId), Events = sum(Events) by Tbl, OSPlatform
| order by Tbl asc, Devices desc
```

**Triage.** First, look at `DeviceImageLoadEvents` against your Linux platforms. Microsoft describes that table as DLL loading events and every platform-specific column on it describes a Windows construct, so a zero against Linux is the expected result and tells you not to build a mod_php hunt on it. Second, check whether `DeviceNetworkEvents` carries `InboundConnectionAccepted` on Linux, because A5's inbound signal depends on it. Third, record the Linux device count per table, because that number is the real ceiling on what the php2shell half of this pack can see.

## D-D0. What `SslConnectionInspected` actually contains in your tenant

**Detection candidate or hunt:** neither. **Needs:** `DeviceNetworkEvents`, which means Defender for Endpoint network protection. **Lookback:** 1 day. **Volume:** 20 rows. **Why it exists:** no vendor has published what a forged-certificate interception looks like in Defender telemetry, and in particular whether `SslConnectionInspected` populates the full issuer chain or only the leaf issuer. That determines whether D-D1 can work at all.

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType =~ "SslConnectionInspected"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, AdditionalFields
| take 20
```

**Triage.** First, read `AdditionalFields` and note which keys are present. The keys confirmed in public query material are `issuer`, `subject`, `direction` and `ja3`. Second, establish whether `issuer` holds a full distinguished name or just a common name, which decides whether the `O=eMudhra` test in D-D1 can be a filter or only an output column. Third, establish whether any intermediate beyond the leaf's direct issuer is represented. If only the leaf issuer appears, D-D1 is still correct for this case, because the compromised certificates are the direct issuers of any forged leaf, but an attacker who chained through an extra self-made intermediate would not appear.

---

# Group A: php2shell exposure

Three questions: which hosts run PHP, which run an affected version, which are reachable from the internet. A4 and A5 both answer the third; A5 is the fuller version and needs more licensing.

One point governs this whole group. Distributions backport the fix without changing the upstream version string, so a version comparison alone produces false negatives on vendor packages. A host reporting `8.2.28` from Debian may already carry the patch. Treat the version verdict as a sorting aid, not an answer, and confirm on the host with the package manager, not with `php -v`, because `php -v` may be a different binary from the one serving requests.

A second point governs the exposure part. Microsoft documents that only Windows devices onboarded to Defender for Endpoint can be identified as internet-facing. PHP mostly runs on Linux. So the internet-facing signal is weakest exactly where the risk is highest.

## A1. PHP inventory with a branch-aware version verdict

**Detection candidate or hunt:** hunt. **Needs:** `DeviceTvmSoftwareInventory`. **Licence note: requires Defender for Endpoint with vulnerability management data. Core vulnerability management ships with Defender for Endpoint Plan 2. The table returns no rows otherwise.** **Lookback:** none possible. `DeviceTvmSoftwareInventory` has no `Timestamp` column, it is a current-state snapshot, so the `ago()` filter applies only to the `DeviceInfo` side. **Volume:** one row per PHP package per host, tens to low hundreds. **False positives:** the string `php` matches application packages such as phpMyAdmin that are not the interpreter, so read `SoftwareVendor` and `SoftwareName` before acting. **Will miss:** PHP inside container images, PHP bundled in appliances, and any host without a Defender sensor. It will also mark backported vendor packages as affected.

```kql
// PHP inventory, with the upstream fixed releases applied per branch.
// Fixed: 8.5.12, 8.4.27, 8.3.36, 8.2.35. Branches below 8.2 have no upstream fix.
DeviceTvmSoftwareInventory
| where SoftwareName contains "php" or SoftwareVendor contains "php"
| extend Branch = extract(@"^(\d+\.\d+)", 1, SoftwareVersion)
| extend PatchLevel = toint(extract(@"^\d+\.\d+\.(\d+)", 1, SoftwareVersion))
| extend FixedAt = case(
    Branch == "8.5", 12,
    Branch == "8.4", 27,
    Branch == "8.3", 36,
    Branch == "8.2", 35,
    int(null))
| extend VersionVerdict = case(
    isempty(Branch),                  "Version string not parseable, check by hand",
    isnull(FixedAt),                  "Branch has no upstream fix, treat as affected",
    isnull(PatchLevel),               "Patch level not parseable, check by hand",
    PatchLevel >= FixedAt,            "At or above upstream fixed release",
                                      "Below upstream fixed release")
// explicit rank, because alphabetical order on the verdict string puts the safe rows first
| extend VerdictRank = case(
    VersionVerdict == "Branch has no upstream fix, treat as affected", 0,
    VersionVerdict == "Below upstream fixed release",                  1,
    VersionVerdict == "At or above upstream fixed release",            3,
                                                                      2)
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, OSPlatform, OSDistribution, IsInternetFacing, MachineGroup, ExposureLevel)
        by DeviceId
  ) on DeviceId
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, Branch,
          VerdictRank, VersionVerdict, OSPlatform, OSDistribution, IsInternetFacing,
          MachineGroup, ExposureLevel
| order by VerdictRank asc, DeviceName asc
```

**Triage.** First, work rank 0 and rank 1 before anything else: rank 0 hosts cannot be patched upstream and need the configuration mitigations instead. Second, for anything marked "Below upstream fixed release" on a Linux host, check the distribution changelog on the host rather than trusting the version string. Third, cross-check `IsInternetFacing` against your own perimeter records, because Defender will not set it on Linux.

**Evasion and gaps.** Nothing an attacker does affects this query. The gap is coverage, not evasion.

## A2. PHP actually observed running, without vulnerability management data

**Detection candidate or hunt:** hunt. **Needs:** `DeviceProcessEvents`, so Defender for Endpoint on the host. No vulnerability management data. **Lookback:** 14 days. **Volume:** one row per host, tens to low hundreds. **False positives:** CLI PHP for cron and build jobs appears here and is not a web attack surface. **Will miss:** mod_php, because mod_php runs inside the Apache process and creates no `php` process. A2 and A3 together are needed.

The regex matters. On Debian and Ubuntu the `php8.2-fpm` package installs `/usr/sbin/php-fpm8.2`, so `FileName` is `php-fpm8.2`. Alpine ships `php-fpm82`. An exact-match list of `"php-fpm"` misses every one of those, which is most of the Linux web tier.

```kql
let lookback = 14d;
let phpBinaries = dynamic(["php","php-fpm","php-cgi","php7","php8","lsphp","frankenphp",
                           "php.exe","php-cgi.exe","php-win.exe"]);
// catches php8.2, php-fpm8.2, php-fpm82, lsphp81, php-cgi, php-win
let phpRe = @"(?i)^(ls)?php[0-9.]*(-?fpm[0-9.]*|-cgi|-win)?(\.exe)?$";
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ (phpBinaries) or FileName matches regex phpRe
     or InitiatingProcessFileName in~ (phpBinaries) or InitiatingProcessFileName matches regex phpRe
| extend IsPhpChild = (FileName in~ (phpBinaries) or FileName matches regex phpRe)
| extend PhpBinary = iff(IsPhpChild, FileName, InitiatingProcessFileName),
         PhpPath   = iff(IsPhpChild, FolderPath, InitiatingProcessFolderPath),
         RunAs     = iff(IsPhpChild, AccountName, InitiatingProcessAccountName)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Events = count(),
            Binaries = make_set(PhpBinary, 15), Paths = make_set(PhpPath, 25), Accounts = make_set(RunAs, 15)
        by DeviceId, DeviceName
| order by LastSeen desc
```

**Triage.** First, separate web-serving PHP from CLI PHP by looking at `Accounts`: a web worker account means a request path exists. Second, compare the host list against A1 to find hosts running PHP that the inventory does not list, which is usually a container or an appliance. Third, check `Paths` for binaries outside the distribution package paths, which are the ones the package manager will not update.

**Evasion.** A renamed interpreter defeats both the list and the regex.

## A3. mod_php, from inventory rather than image load

**Detection candidate or hunt:** hunt. **Needs:** `DeviceTvmSoftwareInventory`, so Defender for Endpoint with vulnerability management data. **Lookback:** none possible, snapshot table. **Volume:** very low, a handful of hosts. **False positives:** near zero, the package names are specific. **Will miss:** mod_php built from source, mod_php inside a container image, and any host the inventory does not cover.

mod_php is the highest-risk shape, because the request triggers the bug before any application code runs. It is also the shape A2 cannot see, because the interpreter is loaded into the web server process and spawns nothing.

Do not build this on `DeviceImageLoadEvents` matching `libphp*`. Microsoft describes that table as DLL loading events, every platform-specific column on it describes a Windows construct, and `libphp8.3.so` is a shared object rather than a DLL. On Linux it would most likely return nothing, and a zero would read as "no mod_php". Run P-2 if you want to see that for yourself. This query asks the package manager's question instead, through the inventory.

```kql
// mod_php is shipped as a distinct package on every distribution, so the package name carries it.
// Debian/Ubuntu: libapache2-mod-php8.2. RHEL family: php (with mod_php) or php-core.
// SUSE: apache2-mod_php8. Windows appliances: the Apache module DLL inside the vendor bundle.
DeviceTvmSoftwareInventory
| where SoftwareName has_any ("mod-php", "mod_php", "libapache2-mod-php")
     or (SoftwareName contains "php" and SoftwareName contains "apache")
| extend Branch = extract(@"(\d+\.\d+)", 1, SoftwareVersion)
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, OSPlatform, OSDistribution, IsInternetFacing, MachineGroup)
        by DeviceId
  ) on DeviceId
| project DeviceName, DeviceId, OSPlatform, OSDistribution, SoftwareVendor, SoftwareName,
          SoftwareVersion, Branch, IsInternetFacing, MachineGroup
| order by DeviceName asc
```

**This is inventory, not observation, and a zero result here is not an answer.** If this returns nothing and you serve PHP through Apache, the finding is not that you have no mod_php. The finding is that your software inventory does not name the module, which means the highest-risk PHP shape in your estate is invisible to every inventory-based query you own, including A1. Record that as a finding rather than moving on.

**Triage.** First, for every host returned, confirm on the host with `apachectl -M | grep php` or `httpd -M | grep php`, which is the authoritative answer. Second, patch these hosts before any host returned only by A1 or A2. Third, for every Apache host in A1 that does not appear here, run the same `apachectl -M` check on a sample, because that tells you whether the inventory gap is real or whether those hosts genuinely use FPM.

## A4. Internet exposure overlay for PHP hosts

**Detection candidate or hunt:** hunt. **Needs:** `DeviceInfo`, plus `DeviceTvmSoftwareInventory` for the host list. **Lookback:** 14 days on `DeviceInfo`. **Volume:** one row per PHP host. **False positives:** `IsInternetFacing` is set from external scan results and accepted inbound connections, so a host behind a NAT that happens to accept a public-sourced connection can be flagged. **Will miss:** all Linux and macOS hosts, per Microsoft's own statement that only Windows devices can be identified as internet-facing. The tag is also removed after 48 hours without new events, so a periodically exposed host can read as not exposed.

```kql
let lookback = 14d;
let phpHosts =
    DeviceTvmSoftwareInventory
    | where SoftwareName contains "php" or SoftwareVendor contains "php"
    | distinct DeviceId;
DeviceInfo
| where Timestamp > ago(lookback)
| where DeviceId in (phpHosts)
| summarize arg_max(Timestamp, *) by DeviceId
| extend Extra = parse_json(AdditionalFields)
| extend ExposureReason      = tostring(Extra.InternetFacingReason),
         ExposedLocalIp      = tostring(Extra.InternetFacingLocalIp),
         ExposedLocalPort    = toint(Extra.InternetFacingLocalPort),
         ExposedTransport    = tostring(Extra.InternetFacingTransportProtocol),
         ScannedPublicIp     = tostring(Extra.InternetFacingPublicScannedIp),
         ScannedPublicPort   = toint(Extra.InternetFacingPublicScannedPort),
         ExposureLastSeen    = todatetime(Extra.InternetFacingLastSeen)
| project DeviceName, DeviceId, OSPlatform, OSDistribution, IsInternetFacing, ExposureReason,
          ExposedLocalIp, ExposedLocalPort, ExposedTransport, ScannedPublicIp, ScannedPublicPort,
          ExposureLastSeen, MachineGroup, ExposureLevel, SensorHealthState
| order by IsInternetFacing desc, DeviceName asc
```

**Triage.** First, for every row where `IsInternetFacing` is true, confirm `ExposedLocalPort` is an HTTP port and `ExposedTransport` is TCP, because an exposed UDP service does not create php2shell reachability. Second, for every Linux row, ignore the column and check your load balancer and WAF configuration instead. Third, check `SensorHealthState`, because an inactive sensor means the exposure data is stale.

All seven `AdditionalFields` keys used here are documented on Microsoft's internet-facing devices page.

## A5. Internet-exposed PHP devices, combining every exposure signal Defender has

**Detection candidate or hunt:** hunt. **Needs:** `DeviceTvmSoftwareInventory`, so Defender for Endpoint with vulnerability management data, and `ExposureGraphNodes`, so Microsoft Security Exposure Management. **Licence note: needs both vulnerability management data and Exposure Management. If you have only one, delete the join you cannot populate, as described after the query.** **Lookback:** 14 days on the network and `DeviceInfo` tables, none possible on the two snapshot tables. **Volume:** low, one row per exposed PHP host. **False positives:** `SoftwareName contains "php"` matches PHP applications that are not the interpreter. **Will miss:** Linux and macOS exposure, containers, and PHP inside appliances.

A4 reads one exposure signal, the Defender internet-facing tag. This query adds three more and combines them: the exposure graph's device property, Microsoft's external scan, and accepted inbound connections from public addresses on web service ports. The idea of combining inventory with inbound-connection evidence comes from FalconForce's FalconFriday hunts, linked in the README; this is an independent implementation.

Four design points. The join key is `DeviceId` throughout, not a truncated hostname, because `extract("^[\\w-]+", 0, DeviceName)` makes two devices with the same leading label in different domains collide. `ExposureGraphNodes.EntityIds` carries a `DeviceInventoryId` which appears to map to the Defender `DeviceId`; verify that mapping holds in your tenant first, with `ExposureGraphNodes | where set_has_element(Categories, "device") | mv-apply Eid = EntityIds on (where tostring(Eid.type) == "DeviceInventoryId") | project NodeName, DeviceId = tostring(Eid.id) | take 10` cross-checked against `DeviceInfo`. The inbound leg filters on `LocalPort`, the service port, not `RemotePort`, which on an accepted inbound connection is the client's ephemeral source port. And private-range exclusion normalises `::ffff:` mapped addresses and uses `ipv4_is_private`, which covers the whole `172.16.0.0/12` block rather than one `/16` of it.

On `ExposureGraphNodes`: Microsoft's exposure graph guidance says `set_has_element` does not use the index on a dynamic column and recommends `has()` for the indexed path, with `set_has_element` alongside because `has()` alone also matches a category such as `prefix_data`. The property paths `NodeProperties.rawData.IsInternetFacing` and `NodeProperties.rawData.exposedToInternet` come from Microsoft's example queries rather than published schema, since the table reference documents `NodeProperties` only as unstructured.

**The gap no query fixes.** Microsoft states that only Windows devices onboarded to Defender for Endpoint can be identified as internet-facing. The confirmed highest-risk php2shell shape is Apache mod_php, which is overwhelmingly Linux. So every exposure signal here is weakest or absent exactly on the hosts that matter most. Treat a Linux row with no exposure flag as unknown, not as not exposed. The Defender internet-facing tag is also removed after 48 hours without new events. Run P-2 to see which of these tables carry Linux data in your tenant at all.

**Sentinel:** none. The vulnerability management tables return no rows in Sentinel, and `ExposureGraphNodes` belongs to Exposure Management in the Defender portal. Defender XDR advanced hunting only.

```kql
// Requires Defender for Endpoint with vulnerability management data (DeviceTvmSoftwareInventory)
// and Microsoft Security Exposure Management (ExposureGraphNodes). Defender XDR only, not Sentinel.
// DeviceTvmSoftwareInventory and ExposureGraphNodes are snapshot tables with no Timestamp column,
// so the time filters below apply only to DeviceNetworkEvents and DeviceInfo.
let lookback = 14d;
let webPorts = dynamic([80, 443, 8080, 8443, 8000, 8880]);
// 1. PHP hosts, keyed on DeviceId rather than a truncated hostname
let phpHosts =
    DeviceTvmSoftwareInventory
    | where SoftwareName contains "php" or SoftwareVendor contains "php"
    | summarize PhpSoftware = make_set(SoftwareName, 20), PhpVersions = make_set(SoftwareVersion, 20)
            by DeviceId, DeviceName;
// 2. Exposure graph nodes flagged as internet facing, joined by DeviceInventoryId.
//    has() for the index, set_has_element() for precision, per Microsoft's exposure graph guidance.
let graphExposed =
    ExposureGraphNodes
    | where (Categories has "device" and set_has_element(Categories, "device"))
         or (Categories has "virtual_machine" and set_has_element(Categories, "virtual_machine"))
    | where isnotnull(NodeProperties.rawData.IsInternetFacing)
         or isnotnull(NodeProperties.rawData.exposedToInternet)
    | mv-apply Eid = EntityIds on (where tostring(Eid.type) == "DeviceInventoryId")
    | extend DeviceId = tostring(Eid.id)
    | where isnotempty(DeviceId)
    | summarize GraphNodeNames = make_set(NodeName, 5) by DeviceId
    | extend GraphExposed = "yes";
// 3. Scanned from the internet by Microsoft's external scan
let scanned =
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where ActionType =~ "InboundInternetScanInspected"
    | summarize ScannedPorts = make_set(LocalPort, 20) by DeviceId
    | extend ScannedFromInternet = "yes";
// 4. Accepted an inbound connection from a public address on a web service port.
//    Filter on LocalPort, the service port, not RemotePort, the client's ephemeral source port.
let inbound =
    DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where ActionType =~ "InboundConnectionAccepted"
    | where LocalPort in (webPorts)
    | where RemoteIPType !in~ ("Private", "Loopback", "LinkLocal")
    | extend RemoteIPv4 = iff(RemoteIP startswith "::ffff:", substring(RemoteIP, 7), RemoteIP)
    | extend RemoteIsPrivate = iff(isnull(ipv4_is_private(RemoteIPv4)), false, ipv4_is_private(RemoteIPv4))
    | where not(RemoteIsPrivate)
    | summarize InboundPorts = make_set(LocalPort, 20), InboundSources = dcount(RemoteIP) by DeviceId
    | extend InboundFromInternet = "yes";
// 5. Defender's own internet-facing tag, plus the exposure detail it carries
let defenderTag =
    DeviceInfo
    | where Timestamp > ago(lookback)
    | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform, OSDistribution,
                        MachineGroup, ExposureLevel, SensorHealthState, AdditionalFields)
            by DeviceId
    | extend Extra = parse_json(AdditionalFields)
    | project DeviceId, IsInternetFacing, OSPlatform, OSDistribution, MachineGroup, ExposureLevel,
              SensorHealthState,
              ExposureReason    = tostring(Extra.InternetFacingReason),
              ExposedLocalPort  = toint(Extra.InternetFacingLocalPort),
              ExposedTransport  = tostring(Extra.InternetFacingTransportProtocol),
              ScannedPublicIp   = tostring(Extra.InternetFacingPublicScannedIp);
phpHosts
| join kind=leftouter graphExposed  on DeviceId
| join kind=leftouter scanned       on DeviceId
| join kind=leftouter inbound       on DeviceId
| join kind=leftouter defenderTag   on DeviceId
| extend InternetAccessible = iff(
    GraphExposed == "yes" or ScannedFromInternet == "yes"
        or InboundFromInternet == "yes" or IsInternetFacing == true,
    "yes", "")
| where isnotempty(InternetAccessible)
| project DeviceName, DeviceId, OSPlatform, OSDistribution, PhpSoftware, PhpVersions,
          InternetAccessible, GraphExposed, ScannedFromInternet, InboundFromInternet, IsInternetFacing,
          ExposureReason, ExposedLocalPort, ExposedTransport, ScannedPorts, InboundPorts, InboundSources,
          ScannedPublicIp, MachineGroup, ExposureLevel, SensorHealthState
| order by DeviceName asc
```

**Triage.** First, cross-reference every row against A1's `VerdictRank` and patch the exposed hosts with an affected version first. Second, read `ExposedLocalPort`, `ExposedTransport` and `InboundPorts`: a host flagged as exposed on a non-HTTP port is not php2shell-reachable and belongs lower in the queue. Third, check `SensorHealthState`, because an inactive sensor makes every exposure column in this row stale.

**Evasion and limits.** Nothing an attacker does affects this query. The limits are the ones above: Windows-only exposure identification, the 48-hour tag decay, no container visibility, and the `php` substring matching applications rather than the interpreter.

**Dropping a join.** If you have vulnerability management data but not Exposure Management, delete the `graphExposed` let block and its join line, and remove `GraphExposed` from the `extend` and the `project`. If you have Exposure Management but not vulnerability management data, replace `phpHosts` with the A2 output, which derives the PHP host list from observed process telemetry instead of from inventory, and the A3 output for the mod_php hosts.


---

# Group B: php2shell exploitation attempts at the request layer

This is where the only real specificity lives. It is also where your endpoint telemetry cannot help you.

The single highest-value indicator is `PHP_SESSION_UPLOAD_PROGRESS` present in an HTTP POST body. It is the one php2shell indicator shipped in a production IDS signature, Corelight Suricata SID 3000650. It requires request body visibility. Defender endpoint tables do not carry HTTP request bodies, and neither do standard web server access logs. That indicator lives in WAF, reverse proxy or IDS data or nowhere.

Two further constraints before you run anything here.

The two CVEs need different request-level detections. CVE-2026-109618 is triggered by a multi-megabyte urlencoded or multipart POST with an oversized field name. The smallest triggering field name is put at around 1 MiB, and ASLR brute-forcing at around 590 oversized requests over about 15 minutes, both per Abstract Security and uncorroborated by any other vendor. Size-based rules work on this CVE. CVE-2026-109619's exploit body is roughly 450 bytes. Size-based rules do not work on it at all.

Recorded Future's point also applies: exploitation occurs below the application layer, so expect limited application-log context. The request shape matters, not the URL. Any hunt keyed on specific request paths will miss, and no request paths have been published anyway.

## What Defender XDR can and cannot reach in this group

Of the indicators in this group, Defender endpoint tables can reach one, indirectly. Everything else has no Defender equivalent, and no query here pretends otherwise.

| Indicator | Defender XDR equivalent |
|---|---|
| `PHP_SESSION_UPLOAD_PROGRESS` in POST body | None. No request body in any Defender table. |
| `PHPSESSID` as a multipart form field | None. Same reason. |
| Serialized PHP or `<?php` in a multipart filename | None. Same reason. |
| POST body size, field name length | None. No request size in any Defender table. |
| Burst of large POSTs per source | None that is worth running. See the note below. |
| PHP fatal error, memory limit messages | None. Defender does not read web server error logs. |
| Apache `AH00052` child exit | Partial, B-D1, inferred from worker respawn bursts. |

There is deliberately no Defender query counting accepted inbound connections per source per minute. It would count connections rather than requests, HTTP keep-alive means one connection can carry many POSTs, and it cannot see the method or the size, so the thing it counts is not the thing the indicator describes. The Sentinel queries B-S1 through B-S6 cover the rest of this group properly.

## B-D1. PHP or Apache worker respawn bursts

**Detection candidate or hunt:** hunt. **Needs:** `DeviceProcessEvents` on the web tier, which in practice means Defender for Endpoint on Linux. Confirm with P-2 first. **Lookback:** anchored to 17 October 2026, Amazon's earliest honeypot observation. **Volume:** depends entirely on your baseline, which is why the threshold needs measuring. **False positives:** a deploy, a config reload, an `apachectl graceful`, a traffic spike, or a `pm.max_requests` setting that recycles workers aggressively will all produce this. **Will miss:** CVE-2026-109619, which is memory-only in-process and produces no worker crash. This query is a proxy for the 109618 crash loop, nothing more.

CVE-2026-109618 works by exhausting `memory_limit` during `$_POST` parsing, repeatedly, while brute-forcing ASLR. On a prefork or FPM pool that means dead children and new children. The parent spawning an unusual number of workers in a short window is the endpoint-visible shadow of that.

```kql
let huntStart = datetime(2026-10-17 00:00:00);   // Amazon's earliest honeypot observation
let respawnBaseline = 200;   // <YOUR_WORKER_RESPAWN_BASELINE>: measure the 99th percentile first
let webServers = dynamic(["httpd","apache2","nginx","caddy","httpd.exe"]);
// catches php-fpm, php-fpm8.2, php-fpm82, lsphp81, php-cgi
let phpRe = @"(?i)^(ls)?php[0-9.]*(-?fpm[0-9.]*|-cgi|-win)?(\.exe)?$";
DeviceProcessEvents
| where Timestamp >= huntStart
| where ActionType =~ "ProcessCreated"
| where FileName in~ (webServers) or FileName matches regex phpRe
| where InitiatingProcessFileName in~ (webServers) or InitiatingProcessFileName matches regex phpRe
| summarize ChildSpawns = count(), Children = make_set(FileName, 5)
        by DeviceId, DeviceName, InitiatingProcessFileName, Window = bin(Timestamp, 5m)
| where ChildSpawns > respawnBaseline
| order by ChildSpawns desc
```

**Triage.** First, establish the baseline before you trust the threshold: run the same query with `respawnBaseline = 0` over 14 days and take the 99th percentile per host. Second, for any genuine spike, pull the web server error log on that host for the same 5 minute window and look for the patterns in B-S4. Third, check whether a deploy or a service restart landed in that window before escalating.

**Evasion.** An attacker who paces requests to stay under the threshold will not appear. An attacker targeting memory disclosure rather than code execution may never crash a worker at all.

---

# Group C: php2shell post-exploitation on the host

Read this before running anything in this group.

**No source has published an observed php2shell process chain.** Every pattern below is vendor-expected behaviour, not observed behaviour. Huntress, SOC Prime and Abstract Security each publish lists of child processes they expect a php2shell intrusion to produce. None of them states it has seen one. No source confirms a single successful compromise of a production system: exploitation attempts are confirmed from 17 October, successful exploitation is not. So these queries will not tell you "this is php2shell". They will tell you "something executed from a web context", which is worth knowing whatever caused it.

Two mechanism points that bound the whole group.

CVE-2026-109619 gives control of the instruction pointer in-process. The initial exploitation step is memory-only inside the worker and produces no child process and no file write by itself. A process-creation hunt catches only the attacker's next action. If the goal was memory disclosure rather than execution, which is the path Wiz demonstrated, there may be no process artifact at all.

Code runs as the web worker account, not root. So the account on these events is the signal, and a hit under root is more likely to be something else.

One specific thing not to build on. Huntress describes a case where a PHP FastCGI process wrote a small PHP file with random marker strings into the first writable temp directory, executed it, deleted it, and printed `!notwrtbl!` when nothing was writable. Huntress states explicitly that this is **not** related to php2shell. Do not treat that pattern as a php2shell indicator.

Two coverage realities. Defender process telemetry exists only where a sensor is installed, and the confirmed highest-risk shape, Apache mod_php, is overwhelmingly Linux. If Defender for Endpoint is not deployed to your web tier, this group covers the least likely population. Containerised PHP produces nothing here unless the container host runs a sensor with container visibility. Run P-2 to see the real numbers.

All five queries share the same parent definition, which combines a stable exact-match list for the web servers with a regex for the PHP binaries, because the Debian family installs `php-fpm8.2` rather than `php-fpm`.

## C-D1. Web server or PHP worker spawning a shell, interpreter, download tool or recon command

**Detection candidate or hunt:** hunt on a general estate. It becomes a detection candidate if you scope it to a web tier where you know PHP never shells out, which is worth establishing. **Needs:** `DeviceProcessEvents`, Defender for Endpoint on the web tier. **Lookback:** anchored to 17 October 2026. **Volume:** on a tuned web tier, near zero. Untuned, moderate: PHP applications shell out for image processing, mail, archive handling and dependency management. **False positives:** `composer`, `convert` and `identify` from ImageMagick, `sendmail`, `gzip`, backup hooks, cron wrappers, health checks. **Will miss:** memory-only exploitation, in-process web shells that never fork, and anything on a host without a sensor.

```kql
let huntStart = datetime(2026-10-17 00:00:00);
let webServers = dynamic(["httpd","apache2","nginx","caddy","httpd.exe","w3wp.exe"]);
let phpRe = @"(?i)^(ls)?php[0-9.]*(-?fpm[0-9.]*|-cgi|-win)?(\.exe)?$|^frankenphp$";
let suspiciousChildren = dynamic([
    // shells
    "sh","bash","dash","zsh","ksh","csh","busybox","cmd.exe","powershell.exe","pwsh.exe",
    // interpreters
    "python","python2","python3","perl","ruby","lua","node",
    // download and transfer
    "curl","wget","ftp","tftp","scp","sftp","rsync","certutil.exe","bitsadmin.exe",
    "nc","ncat","netcat","socat",
    // encoding and staging
    "base64","xxd","openssl","gzip","tar","unzip",
    // recon
    "whoami","id","uname","hostname","ifconfig","ip","netstat","ss","ps","crontab",
    "whoami.exe","ipconfig.exe","net.exe","net1.exe","systeminfo.exe","nltest.exe","tasklist.exe"]);
// edit this before running, it is the whole difference between a hunt and noise.
// the array must stay non-empty or has_any errors.
let allowedCmdFragments = dynamic(["ZZ_NO_MATCH_ZZ"]);   // <YOUR_KNOWN_GOOD_COMMANDLINE_FRAGMENT>
DeviceProcessEvents
| where Timestamp >= huntStart
| where ActionType =~ "ProcessCreated"
// parent OR grandparent, so sh -c "curl ..." is caught on the curl event too
| where InitiatingProcessFileName in~ (webServers) or InitiatingProcessFileName matches regex phpRe
     or InitiatingProcessParentFileName in~ (webServers)
     or InitiatingProcessParentFileName matches regex phpRe
| where FileName in~ (suspiciousChildren) or FileName matches regex phpRe
| where not(ProcessCommandLine has_any (allowedCmdFragments))
| extend ShellWithInlineCommand = ProcessCommandLine matches regex @'(?i)\s-l?c\b'
| project Timestamp, DeviceName, DeviceId, AccountName, AccountDomain,
          InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessId, InitiatingProcessAccountName, InitiatingProcessCommandLine,
          FileName, FolderPath, ProcessCommandLine, ProcessId, ShellWithInlineCommand, SHA256
| order by Timestamp desc
```

**Triage.** First, check `AccountName` against your web worker accounts: a hit under the web worker account is the one that matters, a hit under root or a deploy account usually is not php2shell. Second, read `ProcessCommandLine` and decide in one look whether it belongs to the application: a shell with `-c` and an inline command from a web parent is the shape Abstract Security calls out and is rarely legitimate. Third, take the device and the minute into C-D3 and C-D4 and look for a file write or an outbound connection either side of it.

**Evasion.** An attacker who stays in-process, which CVE-2026-109619 permits, produces nothing here. An attacker who renames a copied interpreter, uses a static binary dropped under a different name, or executes through an already-running process will also miss this list. `FileName in~` is an exact match, so any renaming defeats it. A broader but noisier variant is to invert the test and alert on any child of a web parent that is not on an allow list, which is a better detection if you can maintain the allow list.

## C-D2. Reverse shell command line patterns from a web context

**Detection candidate or hunt:** detection candidate on a web tier, hunt elsewhere. These patterns have very low legitimate use. **Needs:** `DeviceProcessEvents`. **Lookback:** anchored to 17 October 2026. **Volume:** should be zero. **False positives:** health check scripts that use `/dev/tcp` for a port test, named pipes in legitimate build tooling, administrators testing connectivity. **Will miss:** encoded or obfuscated payloads, reverse shells established by a dropped binary rather than a shell one-liner, and in-process shells.

```kql
let huntStart = datetime(2026-10-17 00:00:00);
let webServers = dynamic(["httpd","apache2","nginx","caddy","httpd.exe","w3wp.exe"]);
let phpRe = @"(?i)^(ls)?php[0-9.]*(-?fpm[0-9.]*|-cgi|-win)?(\.exe)?$|^frankenphp$";
// parent filter runs first so the regex only evaluates on a small set.
// (?i) because shell builtins vary in case and PowerShell is case-insensitive.
let revShell = @'(?i)(/dev/(tcp|udp)/|mkfifo|fsockopen|pty\.spawn|socket\.socket|'
                @'\b(bash|sh|zsh|dash)\s+-l?i\b|\bnc(at)?\b[^|;]{0,40}\s-[a-z]*e\b|'
                @'\bsocat\b[^|;]{0,60}\bexec\b|exec\s+\d+<>|0<&\d+|'
                @'IEX\s*\(|FromBase64String|-enc(odedcommand)?\s)';
DeviceProcessEvents
| where Timestamp >= huntStart
| where ActionType =~ "ProcessCreated"
| where InitiatingProcessFileName in~ (webServers) or InitiatingProcessFileName matches regex phpRe
     or InitiatingProcessParentFileName in~ (webServers)
     or InitiatingProcessParentFileName matches regex phpRe
| where ProcessCommandLine matches regex revShell
     or InitiatingProcessCommandLine matches regex revShell
| project Timestamp, DeviceName, DeviceId, AccountName,
          InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, FolderPath, ProcessCommandLine, ProcessId, SHA256
| order by Timestamp desc
```

**Triage.** First, extract the destination address and port from the command line and check it in C-D4 and in your egress logs. Second, check whether the account is a web worker account. Third, if the pattern is `mkfifo` or `/dev/tcp`, look for a second process in the same second completing the pair, because these patterns come in two halves.

**Evasion.** Base64, hex, variable expansion and shell quoting all defeat a command line regex. `$'\x2fdev\x2ftcp'` and `b''a''s''h -i` both survive this query. Treat a zero result as weak evidence.

## C-D3. New or modified files written by a web process, including persistence paths

**Detection candidate or hunt:** hunt. **Needs:** `DeviceFileEvents`. **Lookback:** anchored to 17 October 2026. **Volume:** moderate on a CMS that writes caches and uploads, low on a static application. **False positives:** application caches, compiled templates, log files, session files written by normal session use, CMS plugin and theme installation, deploys that run as the web user. **Will miss:** the exploitation step itself for both CVEs, memory-only activity, and any host without a sensor.

The session save path matters specifically here. The upload-progress mechanism writes session files to disk, and those files are where poisoned content lands. Abstract Security recommends purging them after patching, which means they are also the one place worth looking before you purge.

Path tests use `startswith` and `endswith` on a lowercased copy, not `has_any`. `has` is term-based and treats `/` as a separator, so `FolderPath has_any (dynamic(["/tmp"]))` matches `/usr/lib/tmpfiles.d` and `"/.ssh"` matches `/etc/ssh`.

```kql
let huntStart = datetime(2026-10-17 00:00:00);
let webRoot        = "/var/www/";                   // <YOUR_WEB_ROOT_PATH>
let sessionPath    = "/var/lib/php/sessions";       // <YOUR_SESSION_SAVE_PATH>
let webServers = dynamic(["httpd","apache2","nginx","caddy","httpd.exe","w3wp.exe"]);
let phpRe = @"(?i)^(ls)?php[0-9.]*(-?fpm[0-9.]*|-cgi|-win)?(\.exe)?$|^frankenphp$";
let codeExtensions = dynamic(["php","phtml","php3","php4","php5","php7","php8","phps","pht","phar",
                              "inc","so","sh","py","pl","rb","jsp","aspx","exe","elf"]);
DeviceFileEvents
| where Timestamp >= huntStart
| where ActionType in~ ("FileCreated", "FileModified", "FileRenamed")
| where InitiatingProcessFileName in~ (webServers) or InitiatingProcessFileName matches regex phpRe
| extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
| extend PathLower = tolower(FolderPath)
| extend IsPersistence =
       PathLower startswith "/etc/cron"
    or PathLower startswith "/var/spool/cron"
    or PathLower startswith "/etc/systemd/system"
    or PathLower startswith "/lib/systemd/system"
    or PathLower startswith "/etc/rc.local"
    or PathLower startswith "/etc/ld.so.preload"
    or PathLower endswith "/.ssh"
    or PathLower contains "/.ssh/"
| extend IsStaging =
       PathLower startswith "/tmp"
    or PathLower startswith "/var/tmp"
    or PathLower startswith "/dev/shm"
| extend Bucket = case(
    FileName in~ ("authorized_keys", "authorized_keys2"),               "SSH key file",
    IsPersistence,                                                      "Persistence path",
    PathLower startswith tolower(sessionPath),                          "PHP session store",
    PathLower startswith tolower(webRoot) and Ext in~ (codeExtensions), "Code in web root",
    IsStaging and Ext in~ (codeExtensions),                             "Code in staging path",
    Ext in~ (codeExtensions),                                           "Code elsewhere",
                                                                        "")
| where isnotempty(Bucket)
| project Timestamp, DeviceName, DeviceId, Bucket, ActionType, FolderPath, FileName, Ext, FileSize,
          SHA256, PreviousFolderPath, PreviousFileName,
          InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Bucket asc, Timestamp desc
```

**Triage.** First, work the buckets in order: SSH key file and Persistence path first, then Code in web root, then the rest. Second, for anything in the web root, compare `SHA256` against your deployment artefact and check whether the file exists in version control. Third, for PHP session store hits, retrieve the file content before it is purged and look for serialized object syntax or an unexpected class name.

**Evasion.** Writing through a helper process rather than directly from the web worker breaks the parent filter. Using an extension not on the list, or an extension your web server has been configured to execute as PHP such as a bare `.jpg` under a permissive handler directive, also misses. `FolderPath` is case-sensitive on Linux, which is why every path comparison here runs on a lowercased copy, but the placeholder defaults still have to match your real layout.

## C-D4. Outbound connections initiated by a PHP worker

**Detection candidate or hunt:** hunt, unless your web tier has no legitimate egress, in which case it is a detection candidate and a good one. **Needs:** `DeviceNetworkEvents`. **Lookback:** anchored to 17 October 2026. **Volume:** moderate. A PHP application talking to payment, mail, CDN and update endpoints produces a lot of legitimate outbound traffic. **False positives:** package updates, API integrations, licence checks, webhook deliveries, remote image fetches, telemetry. **Will miss:** connections through your forward proxy if the proxy is the destination, which makes the real destination invisible here.

The `ActionType` filter excludes the whole `*Inspected` family by suffix. That family includes `SslConnectionInspected`, which describes the same outbound connection a second time, so without the suffix exclusion `Connections = count()` is not a connection count. Run P-1 to see the full list in your tenant.

```kql
let huntStart = datetime(2026-10-17 00:00:00);
let webServers = dynamic(["httpd","apache2","nginx","caddy","httpd.exe","w3wp.exe"]);
let phpRe = @"(?i)^(ls)?php[0-9.]*(-?fpm[0-9.]*|-cgi|-win)?(\.exe)?$|^frankenphp$";
let approvedEgress = dynamic(["0.0.0.0"]);   // <YOUR_PROXY_EGRESS_IPS>
DeviceNetworkEvents
| where Timestamp >= huntStart
// drop the inspection event family, which re-reports the same connection, and the inbound types
| where ActionType !endswith "Inspected"
| where ActionType !in~ ("InboundConnectionAccepted", "ListeningConnectionCreated")
| where InitiatingProcessFileName in~ (webServers) or InitiatingProcessFileName matches regex phpRe
| where RemoteIPType !in~ ("Private", "Loopback", "LinkLocal")
| extend RemoteIPv4 = iff(RemoteIP startswith "::ffff:", substring(RemoteIP, 7), RemoteIP)
// ipv4_is_private returns null for a non-IPv4 string, so test explicitly rather than negating null
| extend RemoteIsPrivate = iff(isnull(ipv4_is_private(RemoteIPv4)), false, ipv4_is_private(RemoteIPv4))
| where not(RemoteIsPrivate)
| where not(RemoteIP in~ (approvedEgress))
| extend NonStandardPort = RemotePort !in (80, 443, 25, 53, 587, 465, 993, 995)
| summarize Connections = count(), Ports = make_set(RemotePort, 25), Urls = make_set(RemoteUrl, 25),
            AnyNonStandardPort = max(NonStandardPort),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
        by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteIP
| order by AnyNonStandardPort desc, Connections desc
```

**Triage.** First, work the non-standard-port rows first: Abstract Security, Aikido and SOC Prime all name outbound traffic from the web user on unusual ports as the expected pattern. Second, for each new remote address, check whether the same address appears from any other host in the estate, which separates an application integration from a single compromised worker. Third, correlate the first-seen time against C-D1, C-D2 and C-D3 on the same device.

**Evasion.** Egress over 443 to a cloud-hosted C2 blends into legitimate traffic and will sit at the bottom of this list. Routing through your own forward proxy hides the destination. Beaconing at low frequency keeps `Connections` small.

## C-D5. Every child process shape of PHP and the web servers, rarest first

**Detection candidate or hunt:** hunt. **Needs:** `DeviceProcessEvents`. **Lookback:** anchored to 17 October 2026. **Volume:** high until filtered. **False positives:** everything a PHP application legitimately shells out to do. **Will miss:** memory-only exploitation for both CVEs, and any host without a Defender sensor, which for a Linux web tier is the usual case.

C-D1 asks a closed question: did a web parent spawn something on a suspicious list. This asks the open one: what did web parents spawn at all, grouped by command shape and ordered so the rare shapes come first. It is the right starting point on an estate where you do not yet know what normal looks like, and it catches a renamed binary that C-D1's list cannot.

Three design points. `has "php"` is kept as the broad net because it is whole-term matching: `php-fpm8.2` splits into the terms `php`, `fpm8` and `2`, so `has "php"` matches it while an exact list containing `"php-fpm"` does not, and `contains` would over-match on names such as `phpmyadmin-backup.sh`. The regex backstops it for the Debian and Alpine binary names explicitly. The web server names are included because mod_php runs inside the Apache process, so a shell spawned from mod_php has `httpd` or `apache2` as its parent and never `php`; a PHP-only parent filter misses the highest-risk shape entirely. The two Windows exclusions are substring tests rather than exact matches, because an exact match on `cmd.exe /c "chcp"` lets any whitespace or quoting variation straight through.

A note on anti-joining against a baseline. Comparing against behaviour older than a week is a good noise reducer and a known blind-spot risk. For this incident specifically it is unsafe, because exploitation attempts begin 17 October 2026 and a seven-day baseline taken in late October overlaps the attack window, so you risk baselining the attacker's own activity as normal. If you use an anti-join, take the baseline from before 17 October.

```kql
let huntStart = datetime(2026-10-17 00:00:00);   // Amazon's earliest honeypot observation
// mod_php runs inside the web server, so a shell from mod_php has httpd or apache2 as parent
let webServers = dynamic(["httpd","apache2","nginx","caddy","httpd.exe","w3wp.exe"]);
// backstop for the Debian family's php-fpm8.2 and Alpine's php-fpm82, which an exact list misses
let phpRe = @"(?i)^(ls)?php[0-9.]*(-?fpm[0-9.]*|-cgi|-win)?(\.exe)?$|^frankenphp$";
// Windows noise. Substring tests, not exact matches.
let winNoise = dynamic(['cmd.exe /c "chcp"', "conhost.exe 0xffffffff -ForceV1"]);
// Linux noise, add yours here before running. The array must stay non-empty.
let linNoise = dynamic(["ZZ_NO_MATCH_ZZ"]);   // <YOUR_KNOWN_GOOD_COMMANDLINE_FRAGMENT>
DeviceProcessEvents
| where Timestamp >= huntStart
| where ActionType =~ "ProcessCreated"
| where InitiatingProcessFileName has "php"
     or InitiatingProcessFileName matches regex phpRe
     or InitiatingProcessFileName in~ (webServers)
| where not(ProcessCommandLine has_any (winNoise))
| where not(ProcessCommandLine has_any (linNoise))
// add filters for trusted ProcessCommandLines below
// end filter
| extend Executions = bag_pack_columns(FileName, ProcessCommandLine)
| summarize Count = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Paths = make_set(FolderPath, 10), Hashes = make_set(SHA256, 10)
        by DeviceId, DeviceName, Shape = tostring(Executions), InitiatingProcessFileName,
           AccountName, AccountDomain
| order by Count asc, LastSeen desc
```

The ascending order by `Count` is deliberate. In a hunt like this the rare shapes are the interesting ones and the common shapes are the application doing its job.

**Triage.** First, read the top of the list, the rare shapes, and ask for each whether the application has a reason to run it. Second, filter out the shapes you recognise by adding them between the two filter comments, and re-run until the list is short enough to read. Third, for anything left, check `AccountName` against your web worker accounts and take the device into C-D3 and C-D4.

**Sentinel:** runs unchanged through the Defender XDR connector with `DeviceProcessEvents` forwarded. Change `Timestamp` to `TimeGenerated` if you want predictable behaviour against workspace retention.


---

# Group D: eMudhra certificate authority key compromise

Background that sets the hunt expectation. Eight eMudhra intermediate CA certificates were generated with P-384 private keys whose scalar values were below 256, so the private key is recoverable from the public certificate by trying at most 255 candidates. The keys were not stolen. A faulty key generation ceremony on 30 April 2025 produced a weak key set alongside the correct one, and staff selected the weak keys when preparing the CSRs. Each of the eight keys appears in two certificates, one issued by an eMudhra root and one cross-signed by Sectigo under the AAA Certificate Services root in May 2025. Sixteen certificates, eight keys, all sixteen now revoked with reason `caCompromise`.

**Six of the eight names are TLS CAs. Two are code signing CAs.** Only `EM OV CS CA - G3B` and `EM OV CS CA - G3C` can sign executables. A code signing query that matches all eight names adds no coverage and only costs query time. A TLS interception query should match only the six TLS names. eMudhra's own statement describes all eight as TLS intermediates, which contradicts Mozilla's bug and every independent source. Use Mozilla's split.

**The Sectigo cross-signed counterparts share the same subject common names but have different serials and thumbprints.** This matters differently depending on what you match on. If you match on the issuer common name, which is what Defender gives you, one match covers both certificate sets automatically, because the leaf's issuer distinguished name is the intermediate's subject distinguished name either way. If you match on thumbprints, which is what a Zeek-style source gives you, you need all sixteen values. The thumbprint-based query is D-S3 in the Sentinel file.

**This is a retrospective hunt.** The exposure window ran from roughly May 2025 to 17 October 2026. Chrome, Mozilla, Apple, Android, Microsoft, Go and Node.js have blocked or removed these certificates, and Debian and Ubuntu shipped ca-certificates updates. Red Hat published a workaround with packages still pending for RHEL 6 to 10 as of 21 October, so RHEL hosts, pinned container CA bundles, and embedded or appliance devices that consume neither CRLSet nor OneCRL may still trust them. The question the hunt answers is whether interception happened before the blocks landed, not whether it is happening now.

**Defender XDR advanced hunting retains 30 days.** The exposure window is seventeen months. So any Defender query here can only examine the last 30 days of it, which is the least interesting 30 days, because the blocks were already landing. The full window is only reachable in Sentinel, and only if your workspace retention or archive reaches back that far.

Residual uncertainty sits on the code signing side. eMudhra states none of the eight intermediates issued any end-entity certificates. Chrome independently found no TLS certificates chaining to the six TLS intermediates in Certificate Transparency logs. But Certificate Transparency covers TLS issuance, not code signing. For the two code signing CAs the only assurance is eMudhra's own statement. **Do not skip the code signing hunt on the strength of the CT finding.**

## Where these queries come from

FalconForce published four hunts for these two events in their FalconFriday repository, linked in the README. They are not reproduced here. D-D1 and D-D2 below answer the same two questions, TLS connections to a compromised issuer and executables signed under one, with an independent implementation; if you want the originals, go to the source. **Run D-D0 in the pre-flight section first.** It tells you whether D-D1 can work in your tenant at all.

## D-D1. TLS connections presenting a certificate from a compromised TLS issuer

**Detection candidate or hunt:** detection candidate. **Needs:** `DeviceNetworkEvents` with `SslConnectionInspected`, so Defender for Endpoint network protection. **Lookback:** 30 days, the Defender XDR retention limit, which cannot be extended there. The exposure window is seventeen months, so run D-S1 in Sentinel over a longer window if your retention allows. **Volume:** expected zero. **False positives:** a hit means the connection presented a certificate issued by one of these CAs, which means the communication could have been intercepted, not that it was. **Will miss:** everything before 30 days ago, any host without network protection, and any connection Defender did not inspect.

Four design points. Only the six TLS CA names are matched, because the two code signing CAs cannot appear as the issuer of a TLS server certificate. `O=eMudhra` is an output column rather than a filter, because the full subject distinguished names are not published and it is not confirmed that Defender's `issuer` rendering includes the organisation component; as a hard filter it would risk a false negative on the very thing being hunted. `AdditionalFields has_any ("G3B", "G3C")` runs before the JSON parse as an index-backed prefilter, since Kusto indexes terms of three characters or more. And the CA names are matched with `mv-expand` plus `contains` rather than `has_any`, because `has` is documented for whole indexed terms and the behaviour of a multi-word operand with spaces and hyphens is not.

`AdditionalFields` is documented as a `string` column, not dynamic, so `has_any` on it is a string operation over the serialized JSON and `parse_json` is needed to read individual keys.

```kql
let lookback = 30d;
let tlsCas = dynamic([
    "EM DV TLS CA - G3B", "EM OV TLS CA - G3B", "EM EV TLS CA - G3B",
    "EM DV TLS CA - G3C", "EM OV TLS CA - G3C", "EM EV TLS CA - G3C"]);
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where ActionType =~ "SslConnectionInspected"
| where AdditionalFields has_any ("G3B", "G3C")      // index-backed, three-character terms
| extend Parsed = parse_json(AdditionalFields)
| extend Issuer    = tostring(Parsed.issuer),
         Subject   = tostring(Parsed.subject),
         Direction = tostring(Parsed.direction),
         Ja3       = tostring(Parsed.ja3)
| mv-expand CaName = tlsCas to typeof(string)
| where Issuer contains CaName
| extend IssuerCarriesOrg = Issuer contains "O=eMudhra"
| summarize Connections = count(), DeviceIds = make_set(DeviceId, 50), Devices = make_set(DeviceName, 50),
            Subjects = make_set(Subject, 50), RemoteUrls = make_set(RemoteUrl, 50),
            RemoteIps = make_set(RemoteIP, 50), Ja3s = make_set(Ja3, 20),
            Directions = make_set(Direction, 5), OrgFieldPresent = make_set(IssuerCarriesOrg, 3),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
        by CaName, Issuer
| order by Connections desc
```

**Triage.** First, pull the individual events for any hit and record the subject, so you know which hostname was being presented. Second, establish whether the destination is a service you use: a hit against a payment, identity or software update endpoint is a different problem from a hit against an unknown host. Third, check whether the connections cluster on one network segment or one site, because an interception device sits somewhere specific. Pay particular attention to embedded, appliance or kiosk-style hosts, since those typically consume neither CRLSet nor OneCRL and so remained exposed longest.

**Evasion and limits.** An attacker who used the recovered private keys to sign a certificate for a host your estate never visits leaves nothing here. If Defender's `issuer` field is the leaf issuer only and the attacker chained through an additional self-made intermediate, the compromised CA name would not appear in that field. And nothing before the 30-day window is visible at all, which for this incident is the main limitation rather than a detail.

## D-D2. Executables signed under a compromised code signing CA, and executed

**Detection candidate or hunt:** detection candidate. **Needs:** `DeviceFileCertificateInfo` and `DeviceProcessEvents`. **Lookback:** 30 days in Defender, longer in Sentinel if retention allows, see D-S1. **Volume:** expected zero. **False positives:** none expected, because eMudhra states no end-entity certificates were issued. A hit contradicts that and should go straight to incident response. **Will miss:** anything outside the window, and files that were never executed, which is what D-D3 covers.

Three design points. The match between the certificate table and the process table is a paired `join` on both `DeviceId` and `SHA1`. Testing the two memberships independently, `DeviceId in (...) and SHA1 in (...)`, matches a hash on a device where it was never seen and produces a cross product of false positives on any tenant with more than one hit. `DeviceFileCertificateInfo` emits one row per certificate verification event, so it is deduplicated with `arg_max(...) by DeviceId, SHA1` before the join. And only the two code signing names are matched, because only those can sign a portable executable.

`DeviceFileCertificateInfo` has no `SHA256` column, only `SHA1`, so `SHA1` is the only possible join key. The Sectigo cross-signs share the same subject common name, so the name match covers them without extra thumbprints.

```kql
let lookback = 30d;
let csCas = dynamic(["EM OV CS CA - G3B", "EM OV CS CA - G3C"]);
let signedSoftware =
    DeviceFileCertificateInfo
    | where Timestamp >= ago(lookback)
    | where Issuer has_any ("G3B", "G3C")
    | mv-expand CaName = csCas to typeof(string)
    | where Issuer contains CaName
    | extend IssuerCarriesOrg = Issuer contains "O=eMudhra"
    | summarize arg_max(Timestamp, CaName, Issuer, Signer, SignerHash, IssuerHash,
                        CertificateSerialNumber, SignatureType, IsSigned, IsTrusted,
                        IsRootSignerMicrosoft, CertificateCreationTime, CertificateExpirationTime,
                        IssuerCarriesOrg)
            by DeviceId, SHA1;
signedSoftware
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where isnotempty(SHA1)
    | project ExecTime = Timestamp, DeviceId, DeviceName, SHA1, FileName, FolderPath,
              ProcessCommandLine, ProcessId, AccountName, AccountDomain,
              InitiatingProcessFileName, InitiatingProcessCommandLine
  ) on DeviceId, SHA1
| project ExecTime, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine,
          AccountName, AccountDomain, InitiatingProcessFileName,
          CaName, Signer, Issuer, IssuerCarriesOrg, IssuerHash, CertificateSerialNumber,
          SignatureType, IsTrusted, IsRootSignerMicrosoft, CertificateCreationTime, SHA1
| order by ExecTime desc
```

**Triage.** First, submit `SHA1` for analysis, because a legitimately signed vendor binary and an attacker-signed one are indistinguishable in this table. Second, check `CertificateCreationTime` against the May 2025 to October 2026 exposure window, because a leaf certificate created inside it is far more concerning than one created outside. Third, check `IsTrusted`, which reflects `WinVerifyTrust` and reads false on an endpoint that has consumed the Microsoft block and true on one that has not, so a true tells you that endpoint still accepts the revoked chain.

## The identifier set

All sixteen certificates, from Mozilla Bug 2083449 and the researcher-published `impacted-intermediates.json`. **No query in this pack consumes this datatable.** It is reference material for anyone building their own query, and D-S3 in the Sentinel file carries the subset it needs inline.

```kql
// The 16 revoked eMudhra intermediate certificates. 8 keys, 2 certificates each.
// Source: Mozilla Bug 2083449 and the published impacted-intermediates.json.
// Reference material. No query in this pack reads it.
let EmudhraIntermediates = datatable(CommonName:string, Usage:string, IssuedBy:string,
                                     SerialHex:string, Sha256:string, RecoveredScalar:int)
[
// Issued by emSign Root TLS CA - G3
"EM DV TLS CA - G3B","TLS","eMudhra",
    "a4aee678f23362b4c0e460b772f214",
    "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493", 156,
"EM OV TLS CA - G3B","TLS","eMudhra",
    "6cada367fb1c100088120ea202d568",
    "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B", 155,
"EM EV TLS CA - G3B","TLS","eMudhra",
    "c7c41efe92d825f05eae841a4a82c1",
    "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838", 115,
"EM DV TLS CA - G3C","TLS","eMudhra",
    "588b2e3c2bb8cda13e1a1209254321",
    "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19", 230,
"EM OV TLS CA - G3C","TLS","eMudhra",
    "296926c227a3a1526392b19482a504",
    "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F", 4,
"EM EV TLS CA - G3C","TLS","eMudhra",
    "8009928a64107601af05fa2f19f109",
    "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3", 56,
// Issued by emSign Root CS CA - G3, the only two that can sign executables
"EM OV CS CA - G3B","CodeSigning","eMudhra",
    "7818933f8f85b4619a2b35fba83d0a",
    "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4", 66,
"EM OV CS CA - G3C","CodeSigning","eMudhra",
    "544b7f922c31ae220a4a922916f6e6",
    "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1", 237,
// Sectigo cross-signs under AAA Certificate Services, same subject names, different identifiers
"EM DV TLS CA - G3B","TLS","Sectigo",
    "a024fdf4ba665c785ce4a020483858b7",
    "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE", 156,
"EM OV TLS CA - G3B","TLS","Sectigo",
    "e94223bde92f914e5ab9acabfdac3710",
    "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699", 155,
"EM EV TLS CA - G3B","TLS","Sectigo",
    "d8f8685e4f2bd9d82402a85a1c1eb731",
    "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512", 115,
"EM DV TLS CA - G3C","TLS","Sectigo",
    "91f347f1a5b7d39962b95e0ee4e299d1",
    "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72", 230,
"EM OV TLS CA - G3C","TLS","Sectigo",
    "8d5a4811939ef447d77111cdd9849ae9",
    "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489", 4,
"EM EV TLS CA - G3C","TLS","Sectigo",
    "05f078752dece7a1bb8595d303167171",
    "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F", 56,
"EM OV CS CA - G3B","CodeSigning","Sectigo",
    "41e32b73ac185d6ce0d7480bacf84e69",
    "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8", 66
// The sixteenth certificate, the Sectigo cross-sign of EM OV CS CA - G3C, serial
// d6a5ef613b390f32ef9cdf349f772841, is deliberately left out. Its SHA-256 could not be
// verified against CCADB entry A012350 at the time of writing. Add it when you have
// confirmed the value from CCADB or from the certificate itself. See the note below.
];
EmudhraIntermediates
```

**Fifteen rows, not sixteen.** The SHA-256 of the sixteenth certificate, the Sectigo cross-sign of `EM OV CS CA - G3C`, was rendered inconsistently in the public source, so it is left out of this table and commented out in D-S3 rather than published unverified. Its serial is `d6a5ef613b390f32ef9cdf349f772841` and its CCADB record is A012350. Name-based queries, D-D1, D-D2, D-D3, D-S1 and D-S2, are unaffected, because the cross-sign shares the subject common name. Only thumbprint matching in D-S3 loses that one certificate until the value is confirmed.

**Two naming caveats.** These are common name values, not full subject distinguished names. Mozilla's bug does not publish full subject DNs or SPKI hashes. The organisation component for the eMudhra-operated subjects is `O=eMudhra`. One source renders a name with hyphens, `EM-DV-TLS-CA-G3B`, in an OpenSSL example. That is a filename-style rendering, not the certificate common name. Match the space-separated form.


## D-D3. Compromised code signing certificates on disk and loaded into processes

**Detection candidate or hunt:** detection candidate. **Needs:** `DeviceFileCertificateInfo`, `DeviceFileEvents` and `DeviceImageLoadEvents`. **Lookback:** 30 days, the Defender XDR limit. **Volume:** expected zero. **False positives:** none expected, given eMudhra states no end-entity certificates were issued. A hit contradicts that statement and should be escalated immediately. **Will miss:** anything outside the 30-day window.

**Why this is separate from D-D2.** D-D2 answers "did a signed binary execute". A file can be delivered and signature-verified without ever being executed, and a signed DLL loaded into another process creates no `DeviceProcessEvents` row at all. Since code signing is the side with residual uncertainty, because Certificate Transparency does not cover it, the broader question is worth asking on its own.

The same schema constraint as D-D2 applies. `DeviceFileCertificateInfo` has an `IssuerHash` column, but Microsoft documents it only as a unique hash identifying the issuing CA and names no algorithm, so the published SHA-256 thumbprints cannot be matched against it. `CertificateSerialNumber` is documented as the serial of the certificate the row describes, which is the signed file's own certificate rather than the intermediate, so the published intermediate serials do not belong there either. The `Issuer` string is the sound match, and because the Sectigo cross-signs share the same subject common name it covers all four code signing certificates.

```kql
let lookback = 30d;
let csCas = dynamic(["EM OV CS CA - G3B", "EM OV CS CA - G3C"]);
// dedupe to one row per device and hash, so repeated verification events do not multiply the joins
let flaggedFiles =
    DeviceFileCertificateInfo
    | where Timestamp > ago(lookback)
    | where Issuer has_any ("G3B", "G3C")          // three-character terms, so this is index-backed
    | mv-expand CaName = csCas to typeof(string)
    | where Issuer contains CaName
    | summarize arg_max(Timestamp, DeviceName, CaName, Issuer, Signer, SignerHash, IssuerHash,
                        CertificateSerialNumber, SignatureType, IsSigned, IsTrusted,
                        IsRootSignerMicrosoft, CertificateCreationTime)
            by DeviceId, SHA1
    | project-rename FirstSeen = Timestamp;
union
(
    flaggedFiles
    | extend Surface = "Certificate verification event"
    | summarize Devices = make_set(DeviceName, 50), Signers = make_set(Signer, 20),
                TrustedOnSomeHost = max(IsTrusted),
                FirstSeen = min(FirstSeen), LastSeen = max(FirstSeen), Files = dcount(SHA1)
            by CaName, Surface
),
(
    flaggedFiles
    | join kind=inner (
        DeviceFileEvents
        | where Timestamp > ago(lookback)
        | where isnotempty(SHA1)
        | project DeviceId, SHA1, FolderPath, FileOriginUrl, FileOriginIP
      ) on DeviceId, SHA1
    | extend Surface = "File written to disk"
    | summarize Devices = make_set(DeviceName, 50), Signers = make_set(Signer, 20),
                Paths = make_set(FolderPath, 30), Origins = make_set(FileOriginUrl, 20),
                TrustedOnSomeHost = max(IsTrusted),
                FirstSeen = min(FirstSeen), LastSeen = max(FirstSeen), Files = dcount(SHA1)
            by CaName, Surface
),
(
    flaggedFiles
    | join kind=inner (
        DeviceImageLoadEvents
        | where Timestamp > ago(lookback)
        | where isnotempty(SHA1)
        | project DeviceId, SHA1, FolderPath, InitiatingProcessFileName
      ) on DeviceId, SHA1
    | extend Surface = "Module loaded into a process"
    | summarize Devices = make_set(DeviceName, 50), Signers = make_set(Signer, 20),
                Paths = make_set(FolderPath, 30), LoadedBy = make_set(InitiatingProcessFileName, 20),
                TrustedOnSomeHost = max(IsTrusted),
                FirstSeen = min(FirstSeen), LastSeen = max(FirstSeen), Files = dcount(SHA1)
            by CaName, Surface
)
| order by Surface asc
```

**Triage.** First, work the "Module loaded into a process" rows first, because a loaded module is executing code with no process of its own. Second, use `FileOriginUrl` and `FileOriginIP` on the file-written rows to establish where the file came from, and submit the hash for analysis, since a legitimately signed vendor binary and an attacker-signed one look identical in this table. Third, read `TrustedOnSomeHost`: `IsTrusted` reflects `WinVerifyTrust`, so a true means at least one endpoint still accepts the revoked chain and has not consumed the Microsoft block.

**A known gap.** Defender Vulnerability Management has a `DeviceTvmCertificateInfo` table in preview, documented as certificate information for devices in the organisation from Defender Vulnerability Management. That is the natural place to ask whether the compromised intermediates are still present and trusted in your endpoint certificate stores, which is the question that matters for the hosts that never consumed a revocation update. It has no public column reference, so no query is written against it here. Being a vulnerability management table it will behave like the others in Sentinel, so the query is Defender XDR only. Check the in-portal schema reference and build it. It is probably the single most useful remaining eMudhra query for an estate with long-lived endpoints that do not receive browser-style revocation updates.
