# php2shell and eMudhra: Microsoft Sentinel queries

Companion to `queries-defender-xdr.md`. Query IDs are shared across both files. Verification caveats and the suggested order of work are in `notes-caveats.md`.

Three platform facts shape this whole file.

**The Defender Vulnerability Management tables do not work in Sentinel.** Microsoft states that `DeviceTvmSoftwareInventory` and `DeviceTvmSoftwareVulnerabilities` appear in the Sentinel schema but the data is not ingested, so queries validate, run and return no rows. So every query that depends on them is Defender XDR only.

**The Defender `Device*` event tables do work in Sentinel**, through the Defender XDR connector, provided those tables are selected in the connector configuration. The `Timestamp` column is preserved and `TimeGenerated` is added alongside it, so a Defender query runs unchanged. Use `TimeGenerated` in the filter when you want predictable behaviour against workspace retention and the archive tier.

**This is where the long lookbacks live.** Defender XDR advanced hunting retains 30 days, along with a 10-minute query timeout, a 100,000-row result cap and a 64 MB result size cap. The eMudhra exposure window is seventeen months. If you need to look further back than 30 days, Sentinel is the only place you can.

Every query here parses as published. Where a value has to come from your environment the query ships a working default with the placeholder name in the comment beside it, so you can paste and run first and tune second. Two places need a table or column name only you have: B-S4's custom log leg is commented out, and D-S3 ships Zeek's own field names with a `getschema` step above it.

## Placeholders used in this file

| Placeholder | Appears in | Default shipped | What to put there |
|---|---|---|---|
| `<YOUR_MAX_LEGITIMATE_POST_BYTES>` | B-S2, B-S3, B-S6 | `1048576` | Largest body your applications legitimately accept. |
| `<YOUR_UPLOAD_ENDPOINT_PATHS>` | B-S2, B-S3 | one inert string | URI paths where large uploads are expected. |
| `<YOUR_WAF_VENDORS>` | B-S1 | one inert string | `DeviceVendor` values of your WAF or reverse proxy in CEF. |
| `<YOUR_TLS_INSPECTION_VENDORS>` | D-S2 | one inert string | `DeviceVendor` values of devices that log TLS certificate detail. |
| `<YOUR_WEB_WORKER_UIDS>` | C-S1 | `uid=33`, `uid=48` | Numeric uids of your PHP worker accounts. |
| `<YOUR_WEB_WORKER_ACCOUNTS>` | C-S1 | `www-data`, `apache`, `nginx` | Account names, used as a secondary test. |
| `<YOUR_WEBLOG_CUSTOM_TABLE>` | B-S4 | commented out | Custom log table holding Apache or NGINX error logs. |
| `<YOUR_WEBLOG_MESSAGE_COLUMN>` | B-S4 | commented out | Column in that table holding the raw line, often `RawData`. |

---

# Group A: php2shell exposure, Sentinel

**A1, A3 and A4 are Defender XDR only.** All three depend on `DeviceTvmSoftwareInventory`, which returns no rows in Sentinel. Run them in Defender XDR advanced hunting.

**A2 runs unchanged in Sentinel** if the Defender XDR connector forwards `DeviceProcessEvents`. It is not restated here: take it from the Defender file and change `Timestamp` to `TimeGenerated` in the `where` clause if you want the filter to align with workspace retention. Sentinel is the better place to run it if your retention exceeds 30 days, because a host that ran PHP two months ago and still has it installed will show there and not in Defender.

The governing point from the Defender file applies here too: distributions backport the fix without changing the upstream version string, so a version comparison alone produces false negatives on vendor packages. Treat the version verdict as a sorting aid, not an answer.

## A-S1. PHP inventory from Change Tracking

**Detection candidate or hunt:** hunt. **Needs:** the `ConfigurationData` table, populated by the Change Tracking solution on Azure and Azure Arc machines. **Lookback:** 7 days. **Volume:** one row per PHP package or daemon per machine. **False positives:** the same `php` substring problem as A1, where application packages such as phpMyAdmin match but are not the interpreter. **Will miss:** anything not enrolled in Change Tracking, which in most estates is most of it.

Two column notes. The version lives in `CurrentVersion`, not `SoftwareVersion`. And `ConfigDataType` has documented values, so the filter is explicit rather than left to tenant inspection: Files, Software, WindowsServices, Registry, Daemons.

```kql
let lookback = 7d;
ConfigurationData
| where TimeGenerated > ago(lookback)
| where ConfigDataType in~ ("Software", "Daemons", "WindowsServices")
| where SoftwareName contains "php" or Publisher contains "php"
     or SvcName contains "php" or SvcPath contains "php"
     or SvcName in~ ("apache2", "httpd", "nginx") or SvcPath contains "apache"
// a service row's SoftwareName is an empty string, not null, so coalesce does not separate them
| extend Item = iff(isempty(SoftwareName), SvcName, SoftwareName)
| summarize arg_max(TimeGenerated, CurrentVersion, Publisher, SoftwareType,
                    SvcName, SvcPath, SvcState, SvcStartupType, ConfigDataType)
        by Computer, Item
| extend Branch = extract(@"^(\d+\.\d+)", 1, CurrentVersion)
| extend PatchLevel = toint(extract(@"^\d+\.\d+\.(\d+)", 1, CurrentVersion))
| extend FixedAt = case(Branch == "8.5", 12, Branch == "8.4", 27,
                        Branch == "8.3", 36, Branch == "8.2", 35, int(null))
| extend VersionVerdict = case(
    isempty(Branch),       "No version recorded, check by hand",
    isnull(FixedAt),       "Branch has no upstream fix, treat as affected",
    isnull(PatchLevel),    "Patch level not parseable, check by hand",
    PatchLevel >= FixedAt, "At or above upstream fixed release",
                           "Below upstream fixed release")
// explicit rank, because alphabetical order on the verdict string puts the safe rows first
| extend VerdictRank = case(
    VersionVerdict == "Branch has no upstream fix, treat as affected", 0,
    VersionVerdict == "Below upstream fixed release",                  1,
    VersionVerdict == "At or above upstream fixed release",            3,
                                                                      2)
| project Computer, ConfigDataType, Item, CurrentVersion, Branch, VerdictRank, VersionVerdict,
          Publisher, SoftwareType, SvcState, SvcStartupType, SvcPath
| order by VerdictRank asc, Computer asc
```

**Triage.** First, work rank 0 and rank 1 before anything else. Second, join the machine list to your CMDB to establish which are internet-reachable, since Sentinel has no equivalent of the Defender internet-facing tag. Third, compare the machine list to A2's host list and investigate any machine in only one of them.

---

# Group B: php2shell exploitation attempts at the request layer, Sentinel

These are the queries that matter in this group. Each names the connector or ingestion path that produces its data.

The single highest-value indicator is `PHP_SESSION_UPLOAD_PROGRESS` present in an HTTP POST body. It is the one php2shell indicator shipped in a production IDS signature, Corelight Suricata SID 3000650. It requires request body visibility, which neither Defender tables nor standard access logs provide. That indicator lives in WAF, reverse proxy or IDS data or nowhere.

Two further constraints before you run anything here.

The two CVEs need different request-level detections. CVE-2026-109618 is triggered by a multi-megabyte urlencoded or multipart POST with an oversized field name. The smallest triggering field name is put at around 1 MiB, and ASLR brute-forcing at around 590 oversized requests over about 15 minutes, both per Abstract Security and uncorroborated by any other vendor. Size-based rules work on this CVE. CVE-2026-109619's exploit body is roughly 450 bytes. Size-based rules do not work on it at all. B-S2 and B-S3 target 109618 only. B-S1 is the only query in this group with a real chance against 109619.

Recorded Future's point also applies: exploitation occurs below the application layer, so expect limited application-log context. The request shape matters, not the URL. Any hunt keyed on specific request paths will miss, and no request paths have been published anyway.

A note on the unions in B-S2, B-S3 and B-S5. `union` does not merge a column that appears at two different types: it produces one column per type, suffixed with the type name, and the unsuffixed column does not exist. `W3CIISLog.csBytes` and `scBytes` are `long` and `TimeTaken` is `long`; `AGWAccessLogs.ReceivedBytes` and `SentBytes` are `int` and `TimeTaken` is `real`. So the Application Gateway branch casts to `long` in all three queries. Without that cast the later `order by` and `summarize` lines reference columns that do not exist.

## B-S1. The high-specificity request body and filename markers

**Detection candidate or hunt:** `PHP_SESSION_UPLOAD_PROGRESS` alone is close to a detection candidate, because legitimate use is near zero and Corelight ships it as a signature. The serialized-syntax and open-tag filename markers are hunts. **Needs:** request body or matched-data visibility. Connectors and the table each produces: Azure Application Gateway WAF via the Azure WAF diagnostic connector produces `AGWFirewallLogs`; AWS WAF via the Amazon Web Services S3 WAF connector produces `AWSWAF`; any CEF-forwarding WAF or reverse proxy via the CEF via AMA connector produces `CommonSecurityLog`. **Lookback:** anchored to 17 October 2026. **Volume:** should be very low. If it is not, your WAF is logging a lot of matched data and you should scope by hostname. **False positives:** Corelight states plainly that `PHP_SESSION_UPLOAD_PROGRESS` in a body "does not establish an exploit attempt" and can appear in legitimate traffic, for example in an application that genuinely uses upload progress. Serialized PHP syntax also appears in legitimate API payloads. **Will miss:** everything if your WAF does not log request bodies or matched data, which is the default on most deployments. It will also miss any request your WAF did not inspect, including bodies beyond the inspection size limit.

```kql
let huntStart = datetime(2026-10-17 00:00:00);   // Amazon's earliest honeypot observation
// PHP serialized syntax forms: O:N:" a:N:{ s:N:" R:N;
// deliberately case-sensitive: the type letters are case-significant in PHP's serialization format
let serialized = @'(O:\d+:"|a:\d+:\{|s:\d+:"|R:\d+;)';
// PHP open tags are case-insensitive, so this one is not
let phpOpen = @'(?i)(<\?php|<\?=)';
// PHPSESSID as a form field, in both the multipart-header and urlencoded-argument renderings
let sessField = @'(?i)(name\s*=\s*["'']?PHPSESSID|(^|[&?;\s])PHPSESSID=)';
let wafVendors = dynamic(["ZZ_NO_MATCH_ZZ"]);   // <YOUR_WAF_VENDORS>
union isfuzzy=true
(
    AGWFirewallLogs
    | where TimeGenerated >= huntStart
    | extend Blob = strcat(Message, " ", DetailedMessage, " ", DetailedData, " ", FileDetails)
    | where Blob contains "PHP_SESSION_UPLOAD_PROGRESS"
         or Blob matches regex sessField
         or Blob matches regex serialized
         or Blob matches regex phpOpen
    | project TimeGenerated, Source = "AGWFirewallLogs", SrcIp = ClientIp, TargetHost = Hostname,
              Uri = RequestUri, Rule = RuleId, ActionTaken = Action,
              Evidence = substring(Blob, 0, 512), TxId = TransactionId
),
(
    AWSWAF
    | where TimeGenerated >= huntStart
    | extend Blob = strcat(tostring(HttpRequest), " ", tostring(Headers), " ", Args, " ",
                           tostring(TerminatingRuleMatchDetails), " ",
                           tostring(NonTerminatingMatchingRules), " ", tostring(OversizeFields))
    | where Blob contains "PHP_SESSION_UPLOAD_PROGRESS"
         or Blob matches regex sessField
         or Blob matches regex serialized
         or Blob matches regex phpOpen
    | project TimeGenerated, Source = "AWSWAF", SrcIp = ClientIp, TargetHost = HttpSourceName,
              Uri = Uri, Rule = TerminatingRuleId, ActionTaken = Action,
              Evidence = substring(Blob, 0, 512), TxId = RequestId
),
(
    CommonSecurityLog
    | where TimeGenerated >= huntStart
    | where DeviceVendor in~ (wafVendors)
    // RequestCookies is deliberately excluded: a PHPSESSID cookie is normal traffic
    | extend Blob = strcat(Message, " ", AdditionalExtensions, " ", RequestContext, " ", FileName, " ",
                           DeviceCustomString1, " ", DeviceCustomString2, " ", DeviceCustomString3, " ",
                           DeviceCustomString4, " ", DeviceCustomString5, " ", DeviceCustomString6)
    | where Blob contains "PHP_SESSION_UPLOAD_PROGRESS"
         or Blob matches regex sessField
         or Blob matches regex serialized
         or Blob matches regex phpOpen
    | project TimeGenerated, Source = strcat(DeviceVendor, " ", DeviceProduct), SrcIp = SourceIP,
              TargetHost = DestinationHostName, Uri = RequestURL, Rule = DeviceEventClassID,
              ActionTaken = DeviceAction, Evidence = substring(Blob, 0, 512), TxId = ExtID
)
| order by TimeGenerated desc
```

**Triage.** First, read `ActionTaken`: if the WAF blocked it, you have an attempt and no exposure; if it logged it, go to the host. Second, pivot on `SrcIp` across all three sources and across time, because a single source hitting several PHP hosts is the shape that matters. Third, take `TargetHost` into Group A and establish the PHP version and SAPI on that host, and into Group C to check whether anything executed afterwards.

**Notes on choices made here.** The `PHPSESSID` test is a regex covering both renderings, because the indicator is `PHPSESSID` as a form field and not the session cookie: AWS WAF logs urlencoded arguments as `PHPSESSID=...` in `Args`, while a multipart header reads `name="PHPSESSID"`, and ModSecurity-style matched-data fields vary in quoting. Matching the bare string instead would pull in every cookie in the estate. `union isfuzzy=true` means the query still runs when one of these tables does not exist in your workspace, which matters because you may have one WAF and not three. The ASIM parser is not inside the union, because `isfuzzy` tolerates missing tables and not missing functions, which is why B-S6 is separate.

**Evasion.** The multipart field name can be split across header continuations, case-varied, or padded so the marker falls past the WAF's body inspection limit. Cloudflare reported evasion attempts against its own protections within a day of disclosure. Abstract Security also notes that a start-anchored Suricata rule misfires unless body inspection depth is set above your largest legitimate POST, which is the same class of problem on the IDS side.

## B-S2. CVE-2026-109618 shape: oversized POST bodies to PHP endpoints

**Detection candidate or hunt:** hunt. **Needs:** web access logs with a request size field. Connectors and tables: IIS logs via the Azure Monitor agent produce `W3CIISLog`; Application Gateway access logs via the Azure WAF diagnostic connector produce `AGWAccessLogs`. **Lookback:** anchored to 17 October 2026. **Volume:** moderate, driven entirely by how you set the size threshold relative to your real upload traffic. **False positives:** genuine file uploads, image and video posts, backup and sync endpoints, API bulk writes. **Will miss:** CVE-2026-109619 completely, whose exploit body is around 450 bytes. Also misses anything your access logs do not record a size for.

Note the column semantics. In `W3CIISLog`, `csBytes` is bytes received from the client, which includes the body. In `AGWAccessLogs`, `ReceivedBytes` is the equivalent. Neither carries the field name length, so the 1,000-byte field name indicator is not reachable from access logs: that one needs a WAF with raw body access, which is what B-S1 covers.

```kql
let huntStart = datetime(2026-10-17 00:00:00);
let bodyFloor = tolong(1048576);   // <YOUR_MAX_LEGITIMATE_POST_BYTES>: your largest legitimate POST
let uploadPaths = dynamic(["ZZ_NO_MATCH_ZZ"]);   // <YOUR_UPLOAD_ENDPOINT_PATHS>
union isfuzzy=true
(
    W3CIISLog
    | where TimeGenerated >= huntStart
    | where csMethod =~ "POST"
    | where csBytes > bodyFloor
    | project TimeGenerated, Source = "W3CIISLog", Server = Computer, SrcIp = cIP,
              TargetHost = csHost, Uri = csUriStem, Query = csUriQuery,
              Method = csMethod, Status = scStatus, SubStatus = scSubStatus,
              RequestBytes = csBytes, ResponseBytes = scBytes, ElapsedMs = TimeTaken,
              UserAgent = csUserAgent, Site = sSiteName
),
(
    AGWAccessLogs
    | where TimeGenerated >= huntStart
    | where HttpMethod =~ "POST"
    | where ReceivedBytes > bodyFloor
    // cast to long: W3CIISLog contributes long, and union splits a mixed-type column in two
    | project TimeGenerated, Source = "AGWAccessLogs", Server = InstanceId, SrcIp = ClientIp,
              TargetHost = Host, Uri = RequestUri, Query = RequestQuery,
              Method = HttpMethod, Status = tostring(HttpStatus), SubStatus = tostring(ServerStatus),
              RequestBytes = tolong(ReceivedBytes), ResponseBytes = tolong(SentBytes),
              ElapsedMs = tolong(TimeTaken * 1000), UserAgent = UserAgent, Site = ListenerName
)
| where not(Uri has_any (uploadPaths))
| order by RequestBytes desc
```

**Triage.** First, group by `Uri` and remove the endpoints that legitimately accept large bodies, then re-run. Second, for the remainder, look at `Status`: a 500 or a 503 on an oversized POST to a PHP endpoint is the interesting combination, and B-S5 chases that directly. Third, take the top source addresses to B-S3 to see whether they came in bursts.

**Evasion.** An attacker can keep each request under your threshold and achieve the same memory exhaustion with more requests, or use chunked transfer encoding where some log sources record the size poorly. Setting `post_max_size` down to 8M or 32M at the proxy, which Qualys recommends, both reduces the attack surface and makes this query sharper, because anything above that limit is then anomalous by definition.

## B-S3. Burst of oversized POSTs from one source

**Detection candidate or hunt:** closer to a detection candidate than B-S2, because the burst shape is much less common than a single large POST. Still needs triage. **Needs:** same tables and connectors as B-S2. **Lookback:** anchored to 17 October 2026. **Volume:** low. **False positives:** a multipart chunked upload client, a backup agent, a migration job, a load test. **Will miss:** a paced attack, and CVE-2026-109619 entirely.

Both thresholds come from a single source, Abstract Security: "more than 10 large POSTs per source IP per minute", and roughly 590 oversized requests over about 15 minutes for ASLR brute-forcing. No other vendor corroborates either figure, so treat them as a starting point rather than a measured constant. The 590-over-15-minutes shape is the one that makes this query worth running, because that is a pattern you can see in an access log.

```kql
let huntStart = datetime(2026-10-17 00:00:00);
let bodyFloor = tolong(1048576);   // <YOUR_MAX_LEGITIMATE_POST_BYTES>
let uploadPaths = dynamic(["ZZ_NO_MATCH_ZZ"]);   // <YOUR_UPLOAD_ENDPOINT_PATHS>
let largePosts =
    union isfuzzy=true
    (
        W3CIISLog
        | where TimeGenerated >= huntStart
        | where csMethod =~ "POST" and csBytes > bodyFloor
        | project TimeGenerated, SrcIp = cIP, TargetHost = csHost, Uri = csUriStem,
                  Status = scStatus, RequestBytes = csBytes, Server = Computer
    ),
    (
        AGWAccessLogs
        | where TimeGenerated >= huntStart
        | where HttpMethod =~ "POST" and ReceivedBytes > bodyFloor
        | project TimeGenerated, SrcIp = ClientIp, TargetHost = Host, Uri = RequestUri,
                  Status = tostring(HttpStatus), RequestBytes = tolong(ReceivedBytes), Server = InstanceId
    )
    | where not(Uri has_any (uploadPaths));
largePosts
| summarize LargePosts = count(), Bytes = sum(RequestBytes), MaxBytes = max(RequestBytes),
            Paths = make_set(Uri, 20), Statuses = make_set(Status, 10), Servers = make_set(Server, 20),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by SrcIp, TargetHost, Minute = bin(TimeGenerated, 1m)
| where LargePosts > 10
// second stage drops the per-minute arrays rather than nesting them: make_set over a dynamic
// column produces an array of arrays, which is unreadable in the results grid
| summarize BurstMinutes = count(), TotalLargePosts = sum(LargePosts), PeakPerMinute = max(LargePosts),
            TotalBytes = sum(Bytes), LargestBody = max(MaxBytes),
            FirstSeen = min(FirstSeen), LastSeen = max(LastSeen)
        by SrcIp, TargetHost
| extend BurstSpanMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| order by TotalLargePosts desc
```

**Triage.** First, check whether `BurstSpanMinutes` is around 15 with `TotalLargePosts` in the high hundreds, which is the shape Abstract Security describes. Second, re-run the first `summarize` stage alone for the source and host pair you care about, to get the per-minute paths and statuses this stage drops. Third, correlate the burst window against B-D1 on the target host, because a worker respawn spike in the same minutes turns a maybe into a probably.

## B-S4. PHP fatal errors, memory limit messages and Apache child exits

**Detection candidate or hunt:** hunt. **Needs:** web server error logs in the workspace. Connectors and ingestion paths: Syslog via AMA produces `Syslog`, which carries Apache and PHP messages only if the web server is configured to log to syslog, for example `ErrorLog syslog:local1` in Apache or `error_log = syslog` in PHP. By default both write to files, in which case you need Custom Logs via AMA, which produces a table of your own naming. **The query below runs against `Syslog` alone. The custom log branch is commented out, because only you know the table and column name.** **Lookback:** anchored to 17 October 2026. **Volume:** potentially high on a noisy application, low on a healthy one. **False positives:** a genuinely memory-hungry application, a bad deploy, a plugin leak, an image resize on a large file. **Will miss:** everything if error logs are not collected, which is the common case. It will also miss CVE-2026-109619, whose use-after-free path does not reliably produce a logged fatal error.

Three distinct patterns here, all from the published indicator set. The memory exhaustion triple is "PHP Fatal error", "tried to allocate" and "in Unknown on line 0" appearing together: the `Unknown on line 0` part is the significant one, because it means the error occurred outside any script, which is exactly what request-parsing exhaustion looks like. `Allowed memory size` is the standard PHP memory limit string. `AH00052` is Apache's child-process-exit entry.

Every multi-word pattern uses `contains`. Microsoft documents `has` as matching whole indexed terms and does not document how a multi-word operand behaves, so `contains` is the operator with defined behaviour for phrases such as "tried to allocate".

```kql
let huntStart = datetime(2026-10-17 00:00:00);
Syslog
| where TimeGenerated >= huntStart
| where ProcessName has_any ("httpd", "apache2", "php-fpm", "nginx", "php")
      or SyslogMessage contains "PHP Fatal error"
      or SyslogMessage contains "AH00052"
| project TimeGenerated, Source = "Syslog", Server = Computer, Proc = ProcessName, Line = SyslogMessage
//
// To add file-based error logs, uncomment the union below and substitute your own table and
// column. Custom Logs via AMA names the table; the legacy custom log path puts the raw line
// in RawData. Leaving the placeholder names in place is a syntax error, not a no-op.
//
// union isfuzzy=true
// (
//     <YOUR_WEBLOG_CUSTOM_TABLE>
//     | where TimeGenerated >= huntStart
//     | project TimeGenerated, Source = "CustomWebLog", Server = Computer,
//               Proc = "", Line = tostring(<YOUR_WEBLOG_MESSAGE_COLUMN>)
// )
//
| extend Pattern = case(
    Line contains "PHP Fatal error" and Line contains "tried to allocate"
        and Line contains "in Unknown on line 0", "OOM during request parsing, outside any script",
    Line contains "Allowed memory size",          "PHP memory limit reached",
    Line contains "tried to allocate",            "Allocation failure",
    Line contains "AH00052",                      "Apache child process exit",
    Line contains "PHP Fatal error",              "PHP fatal error, other",
                                                  "")
| where isnotempty(Pattern)
| summarize Hits = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Examples = make_set(substring(Line, 0, 400), 5)
        by Server, Pattern, Hour = bin(TimeGenerated, 1h)
| order by Pattern asc, Hits desc
```

**Triage.** First, prioritise the "OOM during request parsing, outside any script" rows above everything else in this query: that pattern means the failure happened before application code ran, which is the 109618 mechanism and is not what a leaky application looks like. Second, take the hour and the server into B-S2 and B-S3 and find the requests that landed in that window. Third, for Apache child exit clusters, look for one request immediately afterwards that took several seconds, which is the sequence Abstract Security describes.

## B-S5. Server errors on PHP endpoints, and oversized session cookies

**Detection candidate or hunt:** hunt. **Needs:** access logs, as B-S2. The cookie part additionally needs a source that records cookies, which `W3CIISLog.csCookie` does for IIS when cookie logging is enabled. **Lookback:** anchored to 17 October 2026. **Volume:** low once scoped to PHP paths. **False positives:** ordinary application errors, a failing database, a bad release. Large cookies are produced legitimately by some session and consent frameworks. **Will miss:** exploitation that does not crash anything, which includes the whole memory disclosure path Wiz demonstrated.

This query exists because it survives the common case where request bodies are not logged at all. If you cannot see bodies, the error response is the only evidence left.

```kql
let huntStart = datetime(2026-10-17 00:00:00);
let cookieFloor = tolong(4096);      // ordinary PHPSESSID is around 26 to 32 bytes
union isfuzzy=true
(
    W3CIISLog
    | where TimeGenerated >= huntStart
    | where csMethod =~ "POST"
    | where scStatus startswith "5"
         or (isnotempty(csCookie) and csCookie contains "PHPSESSID" and strlen(csCookie) > cookieFloor)
    | project TimeGenerated, Source = "W3CIISLog", Server = Computer, SrcIp = cIP,
              TargetHost = csHost, Uri = csUriStem, Status = scStatus, SubStatus = scSubStatus,
              RequestBytes = csBytes, ElapsedMs = TimeTaken,
              CookieLen = strlen(csCookie), UserAgent = csUserAgent
),
(
    AGWAccessLogs
    | where TimeGenerated >= huntStart
    | where HttpMethod =~ "POST"
    | where HttpStatus >= 500 or ServerStatus >= 500
    // long throughout, to match the IIS branch: a mixed-type column is split by union, not merged
    | project TimeGenerated, Source = "AGWAccessLogs", Server = InstanceId, SrcIp = ClientIp,
              TargetHost = Host, Uri = RequestUri, Status = tostring(HttpStatus),
              SubStatus = tostring(ServerStatus), RequestBytes = tolong(ReceivedBytes),
              ElapsedMs = tolong(TimeTaken * 1000), CookieLen = long(null), UserAgent = UserAgent
)
| summarize Errors = count(), MaxRequestBytes = max(RequestBytes), MaxCookieLen = max(CookieLen),
            MaxElapsedMs = max(ElapsedMs), Statuses = make_set(Status, 10), Paths = make_set(Uri, 20),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by SrcIp, TargetHost, Server, Minute = bin(TimeGenerated, 1m)
| where Errors > 5 or MaxCookieLen > cookieFloor
| order by Errors desc
```

**Triage.** First, look for rows where `Errors` is high and `MaxRequestBytes` is also high, which is the 109618 crash signature from the client side. Second, for any `MaxCookieLen` hit, retrieve the actual cookie value from the raw log and check whether it contains serialized PHP syntax. Third, correlate the minute against B-S4 on the same server.

**Gap worth naming.** One published indicator cannot be reached from any of these tables: an HTTP 200 response whose body contains "Allowed memory size". That requires response body logging, which neither access logs nor WAF logs normally provide. If you have a reverse proxy that can log response bodies on 200s for PHP paths, that is the place to add it.

## B-S6. ASIM variant, for normalised web session data

**Detection candidate or hunt:** hunt. **Needs:** ASIM parsers deployed in the workspace, and a source that populates the optional fields. **Lookback:** anchored to 17 October 2026. **Volume:** as B-S2. **False positives:** as B-S2. **Marked separately from the unions above** because `union isfuzzy=true` tolerates a missing table but not a missing function: if the ASIM parsers are not deployed, this query fails rather than returning nothing.

Read this caveat before using it. `HttpRequestBodyBytes`, `HttpCookie` and `FileName` are all Optional fields in the ASIM Web Session schema, which means most parsers leave them empty. The native `ASimWebSessionLogs` table does not have `HttpRequestBodyBytes`, `HttpResponseBodyBytes`, `HttpCookie` or `HttpStatusCode` at all: the status code lives in `EventResultDetails`, `FileName` and `FileSize` are present, and the closest size field is `SrcBytes`, typed `long`. So form 1 is written against the `_Im_WebSession` parser, and form 2 is what you need if your data lands in the native table.

```kql
// Form 1: via the unifying ASIM parser.
let bodyFloor = tolong(1048576);   // <YOUR_MAX_LEGITIMATE_POST_BYTES>
let serialized = @'(O:\d+:"|a:\d+:\{|s:\d+:"|R:\d+;)';
_Im_WebSession(starttime = datetime(2026-10-17 00:00:00), endtime = now())
| where HttpRequestMethod =~ "POST"
| where HttpRequestBodyBytes > bodyFloor
     or (isnotempty(FileName) and (FileName matches regex serialized
                                   or FileName matches regex @'(?i)(<\?php|<\?=)'))
| project TimeGenerated, SrcIpAddr, DstFQDN, HttpHost, Url, HttpRequestMethod,
          HttpStatusCode, HttpRequestBodyBytes, FileName, FileSize, HttpUserAgent, EventResult, DvcAction
| order by TimeGenerated desc
```

```kql
// Form 2: against the native ASimWebSessionLogs table, which lacks the body-bytes and cookie fields.
let huntStart = datetime(2026-10-17 00:00:00);
let bodyFloor = tolong(1048576);   // <YOUR_MAX_LEGITIMATE_POST_BYTES>
let serialized = @'(O:\d+:"|a:\d+:\{|s:\d+:"|R:\d+;)';
ASimWebSessionLogs
| where TimeGenerated >= huntStart
| where HttpRequestMethod =~ "POST"
| where SrcBytes > bodyFloor
     or (isnotempty(FileName) and (FileName matches regex serialized
                                   or FileName matches regex @'(?i)(<\?php|<\?=)'))
| project TimeGenerated, SrcIpAddr, DstFQDN, HttpHost, Url, HttpRequestMethod,
          EventResultDetails, SrcBytes, DstBytes, FileName, FileSize, HttpUserAgent, EventResult, DvcAction
| order by TimeGenerated desc
```

**Triage.** First, check whether `FileName` is populated in your data at all: if it is always empty, the filename indicators are not reachable through ASIM here and you need B-S1. Second, for any populated `FileName` match, pull the raw WAF record. Third, note that `SrcBytes` in form 2 is the whole source-to-destination byte count for the session, not the request body, so a keep-alive session inflates it and the threshold needs to be higher than in B-S2.

---

# Group C: php2shell post-exploitation on the host, Sentinel

Read the Group C framing in `queries-defender-xdr.md` before running anything here. The short version: no source has published an observed php2shell process chain, so every pattern in this group is vendor-expected behaviour, not observed behaviour. These queries will not tell you "this is php2shell". They will tell you "something executed from a web context", which is worth knowing whatever caused it.

**C-D1, C-D2, C-D3 and C-D4 run unchanged in Sentinel**, provided the Defender XDR connector is forwarding `DeviceProcessEvents`, `DeviceFileEvents` and `DeviceNetworkEvents`. The `Timestamp` column is preserved and `TimeGenerated` is added, so no edit is needed. Switch the filter column to `TimeGenerated` if you want the query to behave predictably against workspace retention and the archive tier. The four query bodies are not duplicated here: take them from the Defender file.

One query here is genuinely Sentinel-native and worth having, because it covers Linux hosts with no Defender sensor.

## C-S1. Shell execution from a web account, from auditd or syslog

**Detection candidate or hunt:** hunt. **Needs:** `Syslog`, populated by Syslog via AMA, with auditd records forwarded to syslog or with `sudo`, `su` and PAM records present. **Lookback:** anchored to 17 October 2026. **Volume:** depends on your audit rule set. **False positives:** cron, logrotate, deploy tooling, monitoring agents running as the web user. **Will miss:** two things. Everything, if auditd execve records are not forwarded, which is the default. And any record that identifies the account numerically only, if your uid list is wrong, which is why the uid list comes first and the account names second.

The uid filter is the point of this version. auditd `SYSCALL` and `EXECVE` records carry numeric identities such as `uid=33` and `auid=4294967295`, not resolved usernames, and `EXECVE` argv is frequently hex-encoded. Filtering the raw syslog line on `www-data` alone drops almost every genuine record and returns an empty result that reads as "no shell execution from a web account". That is the wrong failure mode for a query whose job is to tell you about a gap.

```kql
let huntStart = datetime(2026-10-17 00:00:00);
// Confirm your values on the host with: id -u www-data (33 on Debian and Ubuntu),
// id -u apache (48 on the RHEL family), id -u nginx
let webUids = dynamic(["uid=33", "uid=48", "uid=99"]);   // <YOUR_WEB_WORKER_UIDS>
let webAccounts = dynamic(["www-data", "apache", "nginx"]);   // <YOUR_WEB_WORKER_ACCOUNTS>
let shellish = dynamic(["/bin/sh","/bin/bash","/bin/dash","/usr/bin/python","/usr/bin/python3",
                        "/usr/bin/perl","/usr/bin/curl","/usr/bin/wget","/usr/bin/nc",
                        "/usr/bin/ncat","/usr/bin/socat"]);
Syslog
| where TimeGenerated >= huntStart
| where ProcessName in~ ("audispd", "auditd", "audit", "sudo", "su")
     or SyslogMessage contains "type=EXECVE"
     or SyslogMessage contains "type=SYSCALL"
// numeric uid first, because that is what auditd actually writes; names as a secondary net
| where SyslogMessage has_any (webUids) or SyslogMessage has_any (webAccounts)
| where SyslogMessage has_any (shellish)
     or SyslogMessage contains "/dev/tcp/" or SyslogMessage contains "mkfifo"
| project TimeGenerated, Computer, ProcessName, ProcessID, SeverityLevel,
          Line = substring(SyslogMessage, 0, 900)
| order by TimeGenerated desc
```

**Triage.** First, resolve the `uid=` and `auid=` values in any hit against the host's own `/etc/passwd`, because the defaults above are the common values and not yours. Second, compare the host to the Group A output: a shell from a web account on a host running affected PHP is worth a host triage. Third, if `Syslog` returns nothing for these hosts, record that as a collection gap rather than a clean result, and consider whether a Defender for Endpoint rollout to the web tier is the better fix.

**Evasion and limits.** Syslog carries a truncated, inconsistently formatted view of execve, and hex-encoded `EXECVE` argv defeats every string test here. `has_any` on paths with slashes is doing substring work on an unstructured message, so both false positives and false negatives are likely. This query is a fallback, not a replacement for C-D1.

---

# Group D: eMudhra certificate authority key compromise, Sentinel

Read the Group D framing and the identifier datatable in `queries-defender-xdr.md`. The points that matter most for the Sentinel side:

**Sentinel is where the long lookback lives.** Defender XDR advanced hunting retains 30 days. The eMudhra exposure window ran from roughly May 2025 to 17 October 2026, which is seventeen months. If your workspace retention or archive reaches back that far, Sentinel is the only place the full window is visible. That is the whole reason D-S1 exists as a separate entry.

**Six TLS CA names, two code signing CA names.** Only `EM OV CS CA - G3B` and `EM OV CS CA - G3C` can sign executables. A TLS query matches only the six; a code signing query matches only the two.

**Matching on a common name covers both certificate sets. Matching on a thumbprint does not.** The Sectigo cross-signs share the same subject common names but have different serials and thumbprints. Where you match on the issuer common name, as D-S1 and D-S2 do, one match covers both sets automatically. Where you match on thumbprints, as D-S3 does, you need all sixteen values.

**Residual uncertainty sits on the code signing side.** Certificate Transparency covers TLS issuance, not code signing, so Chrome's CT finding corroborates the "no issuance" claim only for the six TLS CAs. For the two code signing CAs the only assurance is eMudhra's own statement.

## D-S1. D-D1 and D-D2, run over the full exposure window

**These are D-D1 and D-D2 from the Defender file**, with the lookback extended to the full eMudhra exposure window that Defender XDR's 30 days cannot reach, and `TimeGenerated` in place of `Timestamp`. They are repeated here only for the lookback. The design notes for each are with the Defender versions.

**Detection candidate or hunt:** detection candidate, both. **Needs:** the Defender XDR connector with `DeviceNetworkEvents` and `DeviceFileCertificateInfo` selected, plus Defender for Endpoint network protection for the TLS half. **Lookback:** 540 days, which covers May 2025 to now. Reduce it if your workspace retention is shorter, and remember that reading from the archive tier changes the cost. **Volume:** expected zero, both. **False positives:** a TLS hit means the connection presented a certificate issued by one of these CAs, not that it was intercepted. A code signing hit contradicts eMudhra's statement that no end-entity certificates were issued, and should go straight to incident response. **Will miss:** anything outside workspace retention, any connection Defender did not inspect, and any host without network protection. Run D-D0 from the Defender file's pre-flight section first.

```kql
// D-D1 with the lookback extended to the full eMudhra exposure window, which Defender XDR's 30 days cannot reach.
let lookback = 540d;
let tlsCas = dynamic([
    "EM DV TLS CA - G3B", "EM OV TLS CA - G3B", "EM EV TLS CA - G3B",
    "EM DV TLS CA - G3C", "EM OV TLS CA - G3C", "EM EV TLS CA - G3C"]);
DeviceNetworkEvents
| where TimeGenerated > ago(lookback)
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
| summarize Connections = count(), Devices = make_set(DeviceName, 50), DeviceIds = make_set(DeviceId, 50),
            Subjects = make_set(Subject, 50), RemoteUrls = make_set(RemoteUrl, 50),
            RemoteIps = make_set(RemoteIP, 50), Ja3s = make_set(Ja3, 20),
            Directions = make_set(Direction, 5), OrgFieldPresent = make_set(IssuerCarriesOrg, 3),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by CaName, Issuer
| order by Connections desc
```

```kql
// D-D2 with the lookback extended to the full eMudhra exposure window. The paired join on DeviceId
// and SHA1 is deliberate: testing the two memberships independently produces a cross product.
let lookback = 540d;
let csCas = dynamic(["EM OV CS CA - G3B", "EM OV CS CA - G3C"]);
let signedSoftware =
    DeviceFileCertificateInfo
    | where TimeGenerated > ago(lookback)
    | where Issuer has_any ("G3B", "G3C")
    | mv-expand CaName = csCas to typeof(string)
    | where Issuer contains CaName
    | extend IssuerCarriesOrg = Issuer contains "O=eMudhra"
    | summarize arg_max(TimeGenerated, CaName, Issuer, Signer, SignerHash, IssuerHash,
                        CertificateSerialNumber, SignatureType, IsSigned, IsTrusted,
                        IsRootSignerMicrosoft, CertificateCreationTime, IssuerCarriesOrg)
            by DeviceId, SHA1;
signedSoftware
| join kind=inner (
    DeviceProcessEvents
    | where TimeGenerated > ago(lookback)
    | where isnotempty(SHA1)
    | project ExecTime = TimeGenerated, DeviceId, DeviceName, SHA1, FileName, FolderPath,
              ProcessCommandLine, AccountName, AccountDomain, ProcessId
  ) on DeviceId, SHA1
| project ExecTime, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine,
          AccountName, AccountDomain, CaName, Signer, Issuer, IssuerCarriesOrg, IssuerHash,
          CertificateSerialNumber, IsTrusted, SignatureType, CertificateCreationTime, SHA1
| order by ExecTime desc
```

**Triage.** First, for a TLS hit, pull the individual events and record the subject, then establish whether the destination is a service you use. Second, for a code signing hit, submit `SHA1` for analysis, because a legitimately signed vendor binary and an attacker-signed one look identical in this table, and read `CertificateCreationTime` against the May 2025 to October 2026 window. Third, for either, check whether the affected hosts are embedded, appliance or kiosk-style devices, since those typically consume neither CRLSet nor OneCRL and so remained exposed longest.

For the on-disk and loaded-module surfaces, which D-D2 does not cover, run D-D3 from the Defender file with `Timestamp` changed to `TimeGenerated` and the lookback extended.

## D-S2. TLS certificate detail from CEF-forwarding inspection devices

**Detection candidate or hunt:** detection candidate. **Needs:** `CommonSecurityLog`, populated by the CEF via AMA connector from a device that logs certificate detail: a decrypting next-generation firewall, a secure web gateway, a TLS-terminating load balancer. **Lookback:** 90 days as shipped. **This is the most expensive query in the pack and the one most likely to time out interactively**, because it builds a concatenation of eleven columns across a large table. Keep the `DeviceVendor` filter tight, start at 7 days for a demo, and extend only once you know the shape of the result. **Volume:** expected zero. **False positives:** as D-S1. **Will miss:** any traffic not passing through the inspecting device, any traffic the device did not decrypt, and any device that does not emit certificate fields. Which CEF field carries the issuer varies by vendor, which is why the prefilter tests each of them individually rather than naming one.

```kql
let lookback = 90d;   // extend toward 540d only after checking the cost at a shorter window
let tlsCas = dynamic([
    "EM DV TLS CA - G3B", "EM OV TLS CA - G3B", "EM EV TLS CA - G3B",
    "EM DV TLS CA - G3C", "EM OV TLS CA - G3C", "EM EV TLS CA - G3C"]);
let marker = dynamic(["G3B", "G3C"]);
let tlsVendors = dynamic(["ZZ_NO_MATCH_ZZ"]);   // <YOUR_TLS_INSPECTION_VENDORS>
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where DeviceVendor in~ (tlsVendors)
// term-indexed prefilter on each candidate column, before the concatenation.
// has_any takes a single column on the left, so this is written out rather than using a wildcard.
| where Message has_any (marker) or AdditionalExtensions has_any (marker)
     or RequestContext has_any (marker) or Reason has_any (marker)
     or DeviceCustomString1 has_any (marker) or DeviceCustomString2 has_any (marker)
     or DeviceCustomString3 has_any (marker) or DeviceCustomString4 has_any (marker)
     or DeviceCustomString5 has_any (marker) or DeviceCustomString6 has_any (marker)
     or FlexString1 has_any (marker) or FlexString2 has_any (marker)
| extend CertBlob = strcat(Message, " ", AdditionalExtensions, " ", RequestContext, " ", Reason, " ",
                           DeviceCustomString1, " ", DeviceCustomString2, " ", DeviceCustomString3, " ",
                           DeviceCustomString4, " ", DeviceCustomString5, " ", DeviceCustomString6, " ",
                           FlexString1, " ", FlexString2)
| mv-expand CaName = tlsCas to typeof(string)
| where CertBlob contains CaName
| extend OrgFieldPresent = CertBlob contains "O=eMudhra"
| project TimeGenerated, Device = strcat(DeviceVendor, " ", DeviceProduct), Computer,
          CaName, SourceIP, SourceHostName, DestinationIP, DestinationHostName, DestinationPort,
          RequestURL, ActionTaken = DeviceAction, OrgFieldPresent,
          Evidence = substring(CertBlob, 0, 700)
| order by TimeGenerated desc
```

**Triage.** First, establish whether the device blocked or allowed the session, which tells you whether the certificate was trusted at the time. Second, map `SourceIP` to a host and a site, and check whether that host is in a population that never received the revocation updates, such as embedded or appliance devices, or a RHEL host where Red Hat's packages were still pending. Third, take `DestinationHostName` and check your DNS logs for the same name around the same time, looking for a resolution that differs from the legitimate one.

## D-S3. Thumbprint matching against Zeek or Corelight TLS records

**Detection candidate or hunt:** detection candidate. **Needs:** Zeek `ssl.log` data in the workspace. The Corelight Connector Exporter writes to tables named `corelight_ssl` and `corelight_ssl_red`, which is confirmed from Microsoft's connector documentation. The column names in those tables are not in the Azure Monitor table reference, so the query ships Zeek's own `ssl.log` field names and you confirm them first. **Lookback:** 90 days as shipped. **Volume:** expected zero. **False positives:** as D-S1. **Will miss:** traffic not visible to the sensor, and encrypted HTTP that was not decrypted first.

This is the one query in the pack where the SHA-256 thumbprints are usable, because Zeek records certificate chain fingerprints. That is why it needs the full set rather than six common names: the cross-signs have different thumbprints from the eMudhra-issued certificates, and only a combined set covers both chains. **Fifteen of the sixteen are included.** The Sectigo cross-sign of `EM OV CS CA - G3C` is left out because its published SHA-256 could not be verified; see the identifier set in the Defender file. Until you add it, that one certificate is caught only by the issuer-name test in this query, not by thumbprint.

Run this first and fix the two column names in the query below if they differ:

```kql
corelight_ssl | getschema
```

```kql
let lookback = 90d;   // extend toward 540d if retention and archive allow
// 15 of the 16 SHA-256 thumbprints, lower case and un-delimited for comparison. See the note on the sixteenth.
let badThumbprints = dynamic([
    // Issued by eMudhra roots
    "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493",   // EM DV TLS CA - G3B
    "98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b",   // EM OV TLS CA - G3B
    "e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838",   // EM EV TLS CA - G3B
    "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19",   // EM DV TLS CA - G3C
    "cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f",   // EM OV TLS CA - G3C
    "432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3",   // EM EV TLS CA - G3C
    "9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4",   // EM OV CS CA - G3B
    "4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1",   // EM OV CS CA - G3C
    // Sectigo cross-signs, same subject names, different thumbprints
    "45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe",   // EM DV TLS CA - G3B
    "5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699",   // EM OV TLS CA - G3B
    "579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512",   // EM EV TLS CA - G3B
    "62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72",   // EM DV TLS CA - G3C
    "7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489",   // EM OV TLS CA - G3C
    "fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f",   // EM EV TLS CA - G3C
    "a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8"    // EM OV CS CA - G3B
    // EM OV CS CA - G3C, Sectigo cross-sign, serial d6a5ef613b390f32ef9cdf349f772841. Its SHA-256
    // could not be verified against CCADB entry A012350 at the time of writing, so it is left out.
    // Confirm the value from CCADB or the certificate, then add it as a sixteenth entry here.
    ]);
let tlsCas = dynamic([
    "EM DV TLS CA - G3B", "EM OV TLS CA - G3B", "EM EV TLS CA - G3B",
    "EM DV TLS CA - G3C", "EM OV TLS CA - G3C", "EM EV TLS CA - G3C"]);
corelight_ssl
| where TimeGenerated > ago(lookback)
// Zeek ssl.log field names. Confirm against the getschema output above and edit if they differ.
| extend IssuerText = tostring(issuer),
         ChainFps   = tolower(tostring(cert_chain_fps))
| extend ChainFpsClean = replace_string(replace_string(ChainFps, ":", ""), "-", "")
| mv-expand CaName = tlsCas to typeof(string)
| where ChainFpsClean has_any (badThumbprints) or IssuerText contains CaName
| extend MatchedBy = iff(ChainFpsClean has_any (badThumbprints), "Thumbprint", "Issuer name")
| project-reorder TimeGenerated, MatchedBy, CaName, IssuerText, ChainFps
| order by TimeGenerated desc
```

**Triage.** First, read `MatchedBy`: a thumbprint match identifies the exact certificate and therefore tells you whether the eMudhra-issued or the Sectigo cross-signed chain was presented, which a name match cannot. Second, pull the server name and destination address from the record and check them against your known services. Third, if you get a name match with no thumbprint match, that is worth attention in its own right: it means a certificate carrying one of these subject names was presented with a fingerprint not on the published list, which is what a newly minted certificate using a recovered key would look like.

**Why both tests are in the query.** The thumbprint test is exact and identifies the certificate. The name test catches a certificate that uses one of these subject names but is not one of the sixteen published certificates, which is the more interesting case and the one a thumbprint-only query misses. `project-reorder` is used rather than `project`, because `project` takes a column list and drops everything else, so there is no way to say "these columns first, then the rest" with it.
