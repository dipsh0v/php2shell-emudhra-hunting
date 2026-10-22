# php2shell and eMudhra: verification notes, caveats and running order

Companion to `queries-defender-xdr.md` and `queries-sentinel.md`. Query IDs are shared across all three files.

Everything in the query files was checked against Microsoft's public schema reference and the vendor intelligence listed below. Nothing has been run against a production tenant. The caveats that a one-minute query can settle have been turned into the pre-flight queries P-1, P-2 and D-D0 rather than left as prose.

---

# Verified against Microsoft's documentation

1. **`DeviceFileCertificateInfo` has 18 columns and no `SHA256`.** `CertificateSerialNumber`, `IsSigned`, `IsTrusted`, `IsRootSignerMicrosoft`, `CrlDistributionPointUrls`, `IssuerHash` and `SignerHash` all exist, so every column D-D2, D-D3 and D-S1 project is real, and `SHA1` is the only possible join key. `IssuerHash` is documented only as "Unique hash value identifying issuing certificate authority (CA)" with no algorithm named, and `CertificateSerialNumber` as "Identifier for the certificate that is unique to the issuing certificate authority (CA)", which is the signed file's own certificate rather than the intermediate. So the published SHA-256 thumbprints and intermediate serials cannot be matched against these columns. The common-name match is the only sound option in Defender data, and it does cover the Sectigo cross-signs, because the leaf's issuer distinguished name is the intermediate's subject distinguished name in both chains.

2. **`ConfigurationData.ConfigDataType` values are documented:** Files, Software, WindowsServices, Registry, Daemons. A-S1 filters on them explicitly.

3. **The ASIM claim in B-S6 is exact.** `ASimWebSessionLogs` has no `HttpRequestBodyBytes`, `HttpCookie` or `HttpStatusCode`. `SrcBytes` is `long`, `EventResultDetails` is documented as "The HTTP status code", and `FileName` and `FileSize` are present. Form 2 is schema-correct, and `SrcBytes` is a session total rather than a body size.

4. **`DeviceTvmCertificateInfo` exists, is Preview, and is a Defender Vulnerability Management table.** Being a vulnerability management table it will behave like the others in Sentinel and return no rows there, so any query built from it is Defender XDR only. It is still the highest-value remaining eMudhra query for an estate with devices that never consumed a revocation update.

5. **The `has_any ("G3B", "G3C")` prefilter really is index-backed.** Microsoft documents that Kusto builds a term index of all terms three characters or more, so a three-character term is on the fast path rather than the scan path. The same page is the basis for choosing `contains` over `has` for the full CA names: `has` is defined for whole indexed terms and multi-word operand behaviour is not documented.

6. **`AdditionalFields` is a `string`, not a dynamic column**, in all four `Device*` event tables, documented as "Additional information about the event in JSON array format". Running `has` against it as a string and using `parse_json` to read keys is therefore the correct handling.

7. **Adjacent `@'...'` string literals concatenate.** Microsoft documents that string literals with no separation, or separated only by whitespace or comments, are combined into a single literal. The multi-line regex in C-D2 is valid KQL.

8. **Everything in A4 verifies.** All seven `InternetFacing*` keys are documented on the internet-facing devices page, along with the statement that only Windows devices onboarded to Defender for Endpoint can be identified as internet-facing, and the 48-hour tag removal. `IsInternetFacing`, `ExposureLevel`, `MachineGroup`, `OSDistribution`, `SensorHealthState` and `AdditionalFields` are all confirmed on `DeviceInfo`.

---

# Not verifiable from public documentation

## Items a pre-flight query settles in your own tenant

9. **`ActionType` value lists are not in the public schema reference.** Microsoft's table pages point to the in-portal schema reference. **P-1** enumerates the real values per table in one minute. The seven values this pack filters on are `ProcessCreated`, `FileCreated`, `FileModified`, `FileRenamed`, `SslConnectionInspected`, `InboundConnectionAccepted` and `InboundInternetScanInspected`. P-1 will also show you the full `*Inspected` family, which C-D4 excludes by suffix.

10. **Microsoft publishes no per-platform table coverage.** Microsoft does not document which advanced hunting tables Linux populates, so measuring is the only way to know. **P-2** reports table coverage by OS platform. This matters most for `DeviceImageLoadEvents` on Linux and for `InboundConnectionAccepted` on Linux, which A5's inbound signal depends on.

11. **`AdditionalFields` keys for `SslConnectionInspected`.** `issuer`, `subject`, `direction` and `ja3` are confirmed from a public query library, not from Microsoft documentation. A `cipher` key is sometimes read in public queries but could not be confirmed, so it is not used. **D-D0** shows you the real keys in one query.

12. **Whether `SslConnectionInspected` carries the full issuer chain or only the leaf issuer.** Nobody has published this, and it determines whether D-D1 and D-S1 can work at all. D-D0 answers it. If only the leaf issuer appears, those queries are still correct for this case, because the compromised certificates are the direct issuers of any forged leaf, but an attacker who chained through an extra self-made intermediate would not appear.

13. **Whether `ExposureGraphNodes.EntityIds` `DeviceInventoryId` equals the Defender `DeviceId` in a given tenant.** A5 joins on that assumption. The property paths `NodeProperties.rawData.IsInternetFacing` and `NodeProperties.rawData.exposedToInternet` appear only inside example queries on Microsoft's exposure graph page, and the table reference documents `NodeProperties` as unstructured, so these are examples rather than published schema. A5's preamble carries a one-line query to settle the `DeviceInventoryId` mapping.

## Items no query settles

14. **`corelight_ssl` column names.** The table names `corelight_ssl` and `corelight_ssl_red` are confirmed from Microsoft's Corelight Connector Exporter documentation, along with `corelight_http`, `corelight_notice`, `corelight_files` and `corelight_conn`. The columns are not in the Azure Monitor table reference. D-S3 ships Zeek's own `ssl.log` field names, `issuer` and `cert_chain_fps`, with a `getschema` step above it.

15. **Whether `coalesce` accepts `bool` arguments.** The reference states only that arguments are scalar and all of the same type, and does not enumerate the supported types. The queries therefore use an explicit `iff(isnull(...), false, ...)` around `ipv4_is_private`, which returns null for a non-IPv4 string.

16. **Whether a wildcard is accepted on the left of `has_any`.** The `has` and `has_any` references both define the left side as a single column and neither mentions a wildcard. D-S2 tests each candidate CEF column individually, which is certain to parse and uses the same term index.

## Intelligence items carried forward from vendor reporting

17. **No attacker IOCs exist for php2shell.** No IPs, no domains, no hashes, no web shell names, no user agents, no request paths. Tenable states "none provided", Huntress's IOC table reads "TBD", and Recorded Future, SOC Prime and Abstract Security all state the same. Every php2shell query in this pack is behavioural or structural for that reason.

18. **No confirmed successful compromise.** Exploitation attempts are confirmed from 17 October 2026, when Amazon observed one against its MadPot honeypot four days before public disclosure. Recorded Future states plainly that the reporting does not establish the full extent of successful exploitation or confirmed compromises. Huntress had not observed in-the-wild exploitation on partner systems as of 21 October, and CISA stated it had not observed exploitation. Everything in Group C is vendor-expected behaviour, not observed behaviour.

19. **Per-CVE attribution of observed exploitation is absent.** No source says which CVE the observed attempts targeted. This matters because the request shapes differ: multi-megabyte for 109618, around 450 bytes for 109619. B-S2 and B-S3 are 109618-only and B-S1 is the only query with a real chance against 109619.

20. **Abstract Security's numbers are one vendor's and uncorroborated.** The 1 MiB smallest triggering field name, the 590 oversized requests over 15 minutes, and the 10-large-POSTs-per-minute threshold all come from the same source. Both query files say so where the numbers appear.

21. **The affected lower bound is disputed.** Google Cloud and Corelight say PHP 5.4 through 8.5.11, all versions, with Corelight giving 5.4.0 as the lower bound. Tenable gives a branch table with 7.4 to 8.1 served only by minimal source backports and 5.4 to 7.3 with no fix. JFrog confirms only the four supported branches. watchTowr and SOC Prime both state the "PHP 5, 7 and 8 in entirety" scope came from the leak and is not confirmed by PHP's own advisory. The GHSA advisory text could not be retrieved at the time of writing. A1 and A-S1 implement the branch table, treat pre-8.2 branches as affected with no upstream fix, and say so in the verdict string. **Confirm the lower bound against GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp before relying on the verdict.**

22. **Distribution backports do not change the version string**, so A1 and A-S1 will produce false negatives on vendor packages and both say so in the preamble. Qualys also makes the related point that `php -v` output may come from a different binary than the one serving requests, so confirm on the host with the package manager.

23. **Corelight's own README carries an unresolved note** to verify the affected ranges and first fixed releases against official PHP advisories and release notes, and describes its version cutoffs as provisional, based on stable releases checked on 18 October 2026. The branch numbers in A1 and A-S1 match Corelight's and share that provisional status.

24. **The sixteenth eMudhra thumbprint**, the Sectigo cross-sign of `EM OV CS CA - G3C`, was rendered in the source with a truncated prefix followed by the full value, and that prefix is the same leading characters as the row's own serial. That looks like a display error in the source table, but it means this one thumbprint of the sixteen is the least trustworthy. **It is therefore left out of the identifier set and of D-S3**, which is the only query that matches on thumbprints, until it can be confirmed from CCADB entry A012350 or from the certificate. The other fifteen are consistent across sources. Name-based queries are unaffected because the cross-sign shares the subject common name.

25. **Full subject distinguished names and SPKI hashes for the eMudhra intermediates are not published.** Mozilla's bug gives common name, serial and SHA-256 only. The organisation component for the eMudhra-operated subjects is `O=eMudhra`. This is why every `O=eMudhra` test in the pack is an output column rather than a filter: as a filter it risks a false negative on the exact thing being hunted.

26. **One source renders a CA name with hyphens**, `EM-DV-TLS-CA-G3B`, in an OpenSSL verification example. That is a filename-style rendering, not the certificate common name. Every query here matches the space-separated form.

27. **Which eMudhra intermediate was deployed in production is not published.** eMudhra says one was. It does not say which.

28. **Conflicting patch commit hashes**, `31c0ea7d7ff` from JFrog against `3584a98bda` from a third-party repository. No query in this pack depends on either.

29. **CISA KEV status.** php2shell is not in CISA's Known Exploited Vulnerabilities catalogue as of 21 October 2026, per watchTowr, SOC Prime and secondhand reporting of CISA's alert. This was not confirmed at source.

## Operational limits worth knowing

30. **Defender XDR advanced hunting limits:** up to 30 days of raw data, a 10-minute query timeout, a 100,000-row result cap, a 64 MB result size cap, and a warning at 10 percent of tenant CPU allocation. The 30 days is the binding constraint for eMudhra, which has a seventeen-month exposure window. The others matter for the Sentinel long-lookback queries: D-S2 is the most likely query in the pack to time out, because it concatenates eleven columns across a large table, and its preamble says to start at a short window.

31. **Containerised PHP is undercounted everywhere.** It produces no `DeviceProcessEvents` unless the container host runs a sensor with container visibility, and `DeviceTvmSoftwareInventory` will generally not enumerate PHP inside an image. Any inventory-style hunt will undercount container workloads. Aikido's own patched image tags such as `php:8.2.34` and `php:8.4.26` are below the fixed releases, so the PHP version inside each image has to be verified rather than inferred from the tag.

32. **Internet-facing identification is Windows-only**, and PHP mostly runs on Linux. This undercuts A4 and A5 on exactly the population that matters. A Linux row with no exposure flag means unknown, not safe.

33. **The Defender Vulnerability Management tables return no rows in Sentinel.** Microsoft states the tables appear in the Sentinel schema but the data is not ingested, so queries validate, run and return nothing. A1, A3, A4 and A5 are therefore Defender XDR only. A2 is not: it uses only `DeviceProcessEvents` and runs in Sentinel, and Sentinel is the better place for it if retention there exceeds 30 days.

34. **The identifier datatable is reference material.** No query in the pack consumes it. D-S3 carries the subset it needs inline.

---

# Design decisions, and the traps they avoid

These are the KQL pitfalls the pack was written around. Each one is findable from documentation alone, without a tenant, and each one produces either a parse error or a silently wrong result.

1. **`union` does not merge a column that appears at two types.** `W3CIISLog.csBytes` is `long` and `AGWAccessLogs.ReceivedBytes` is `int`. `union` emits one column per type with a type suffix, and the unsuffixed name does not exist, so a later `order by RequestBytes` or `sum(RequestBytes)` references a column that is not there. B-S2, B-S3 and B-S5 cast the Application Gateway branch to `long`.

2. **Placeholders never sit in a syntactic position.** A string-literal placeholder such as `"<YOUR_WEB_ROOT_PATH>"` parses and matches nothing. `toint(<YOUR_MAX_LEGITIMATE_POST_BYTES>)` or `where ChildSpawns > <YOUR_WORKER_RESPAWN_BASELINE>` is a syntax error, as is a placeholder table name in a union leg. Every query ships a working default with the placeholder name in a comment beside it, so paste-and-run works before tuning.

3. **`project ... , *` is a parse error.** `project` takes a column list and drops everything else; wildcards belong to `project-away`, `project-keep` and `project-reorder`. D-S3 uses `project-reorder`.

4. **`DeviceImageLoadEvents` is a Windows DLL-load table.** Matching `libphp*` in it on Linux most likely returns nothing, and that zero reads as "no mod_php". A3 asks the software inventory instead and states explicitly that a zero result means the inventory does not name the module, not that the module is absent.

5. **Exact-match lists miss distribution-specific binary names.** On Debian and Ubuntu the `php8.2-fpm` package installs `/usr/sbin/php-fpm8.2`; Alpine ships `php-fpm82`. `in~ ("php-fpm")` misses all of them, which is most of the Linux web tier. `has "php"` matches them because `php-fpm8.2` splits into the terms `php`, `fpm8` and `2`. Every PHP-side test pairs a regex with the list, and C-D5 keeps `has "php"` as the broad net.

6. **A constant literal is not a `summarize` aggregation.** `summarize GraphExposed = "yes" ... by DeviceId` is not the documented form. The documented form is `summarize by ... | extend Flag="yes"`, which A5 uses.

7. **auditd records carry numeric identities.** `SYSCALL` and `EXECVE` records say `uid=33`, not `www-data`, and `EXECVE` argv is often hex-encoded. C-S1 tests numeric uids first with account names as a secondary net, so that a zero means a collection gap rather than a false "no shell execution from a web account".

8. **`has` is term-based and treats `/` as a separator.** `FolderPath has_any (dynamic(["/tmp"]))` matches `/usr/lib/tmpfiles.d`, and `"/.ssh"` matches `/etc/ssh`. C-D3 uses anchored `startswith` and `endswith` on a lowercased copy of the path. `startswith` is used rather than `hasprefix` because it is the operator whose behaviour on slash-delimited paths is unambiguous.

9. **`matches regex` is case-sensitive.** PHP open tags are case-insensitive, so B-S1's `(<\?php|<\?=)` carries `(?i)`, as do C-D2's PowerShell patterns. The serialized-syntax regex stays case-sensitive, because `O:`, `R:`, `a:` and `s:` are case-significant in PHP's serialization format.

10. **`has` and `set_has_element` on `ExposureGraphNodes` belong together.** Microsoft says `set_has_element` does not use the index on a dynamic column and recommends `has()` for the indexed path, with `set_has_element` alongside because `has()` alone also matches a category such as `prefix_data`. A5 uses both.

11. **Alphabetical ordering on a verdict string puts the safe rows first.** A1 and A-S1 carry an explicit `VerdictRank`.

12. **`coalesce` does not separate empty strings from null.** A service row's `SoftwareName` in `ConfigurationData` is an empty string rather than null, so `coalesce(SoftwareName, SvcName)` collapses every daemon row into one group key. A-S1 uses `iff(isempty(SoftwareName), SvcName, SoftwareName)`.

13. **`DeviceFileCertificateInfo` emits one row per verification event.** A file verified many times multiplies any join output. D-D2 and D-D3 deduplicate with `arg_max(...) by DeviceId, SHA1` before joining.

14. **Relative lookbacks drift off the exploitation window.** `ago(7d)` is correct on 22 October 2026 and wrong by the end of the month. Every Group B and Group C query uses `let huntStart = datetime(2026-10-17 00:00:00);`.

15. **The grandchild case matters.** A web shell running `sh -c "curl ..."` produces a `curl` event whose parent is `sh`, not php. C-D1 and C-D2 test `InitiatingProcessParentFileName` as well.

16. **The `*Inspected` event family re-reports the same connection.** Without excluding it by suffix, `Connections = count()` in C-D4 is not a connection count.

17. **B-S4's custom log branch is commented out** because only you know the table and column name, and a placeholder name there is a syntax error rather than a no-op. D-S3 instead ships Zeek's own `ssl.log` field names with a `corelight_ssl | getschema` step above it, because the two column names are the query, and if they differ the failure is an unknown-column error naming the column.

---

# Suggested order of work

1. **P-1, P-2 and D-D0 first.** Three minutes in total, and between them they settle which `ActionType` values exist, which tables carry Linux data, and what `SslConnectionInspected` actually contains. Record the Linux device count per table from P-2, because that number is the real ceiling on what the php2shell half of this pack can see.
2. **A1 and A2**, to establish the PHP population. A2 needs no vulnerability management data, so run it even if A1 returns nothing.
3. **A3**, the inventory-based mod_php check. **A zero result here is not an answer.** If you serve PHP through Apache and this returns nothing, the finding is that your inventory does not name the module, which means the highest-risk PHP shape in your estate is invisible to every inventory-based query you own, A1 included. Confirm on a sample host with `apachectl -M | grep php` before you move on.
4. **A5**, to narrow A1's output to the internet-reachable subset. Remember that a Linux row with no flag means unknown, not safe, and check the `DeviceInventoryId` mapping first.
5. **B-S1**, which is the only query in the pack with real php2shell specificity. If it returns nothing because your WAF does not log request bodies, that result is itself a finding worth recording.
6. **B-S2, B-S3, B-S4, B-S5** from the 17 October anchor. Add B-S6 if your ASIM parsers are deployed.
7. **C-D1 through C-D5** from the same anchor, on the hosts A1 to A3 identified. Add C-S1 for Linux hosts with no sensor, and resolve the uids against the host before trusting a zero.
8. **D-D1, D-D2 and D-D3** for eMudhra in Defender over the last 30 days, then **D-S1** in Sentinel over whatever retention you have, which is the only way to reach most of the exposure window.
9. **D-S2 and D-S3** if you have TLS inspection or Zeek data, because they reach further back than Defender can. Start D-S2 at a short window, because it is the most expensive query in the pack.

Mark D-D1, D-D2, D-D3, D-S1, D-S2, D-S3 and C-D2 as detection candidates. Everything else in the pack is a hunt, and the preambles say so individually.

## Lookback windows, and the three dates in circulation

For php2shell, sources give three different start dates:

- **17 October 2026**, per Amazon, because that is its earliest honeypot observation and it recommends investigations start there.
- **20 October 2026**, per Recorded Future and Abstract Security, with Recorded Future adding "extend hunting to before the disclosures".
- The vulnerable code reaches back to PHP 5.4.0 in 2012, so pre-17-October activity is possible, but nothing in the sources evidences it.

The defensible window is **17 October 2026 forward**, and every php2shell query in the pack is anchored to that date rather than to a relative lookback that drifts.

For eMudhra the window is different in kind: roughly **May 2025 to 17 October 2026**, seventeen months, and the hunt is retrospective. It asks whether interception happened before the blocks landed, not whether it is happening now. Defender's 30 days cannot reach it, which is why D-S1 exists.

## The short version

The most specific php2shell indicator available anywhere is a single string in a POST body, `PHP_SESSION_UPLOAD_PROGRESS`, shipped in exactly one production signature. Most organisations cannot see POST bodies at all. The gap between those two facts is the actual finding. Everything else in the php2shell half of this pack is either inventory work or generic web-context execution detection that would fire on any web shell from any cause.

The eMudhra half is the opposite shape: precise published identifiers, a seventeen-month exposure window, and a telemetry retention limit that means most estates cannot look at most of it. The residual question, whether the two code signing CAs were ever abused, is the one nobody can answer from public data, because Certificate Transparency does not cover code signing and the only assurance is the CA's own statement.
