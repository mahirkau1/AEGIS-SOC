# OPNsense deployment and validation

> Scope: operator-observed AEGIS lab configuration. `[LAB]` = lab evidence or statement; `[KOD]` = verified application behavior. [LAB] OPNsense performs actual blocking, whereas the SOC performs **read-only observation**.

## 1. Establish the VM and isolate the networks

1. **[LAB]** Deploy OPNsense as the gateway for USERS (`em2`), SERVERS (`em3`), DMZ (`em4`) and SECURITY (`em5`). Keep Internet-facing WAN separate from internal zones. **<!-- TODO: fill in exact OPNsense version, WAN/em0/em1 mapping and hypervisor version. -->**
2. **[LAB]** Assign zone gateways in the lab plan: USERS `10.10.20.1/24`, SERVERS `10.10.30.1/24`, DMZ `10.10.40.1/24`, SECURITY `10.10.50.1/24`*. Verify in **Interfaces → Overview / Assignments** and the console using `ifconfig`.
3. **[LAB]** Place DC01 `10.10.30.10` in SERVERS, Kali `10.10.50.100` in SECURITY, and WIN01 in USERS. Note that WIN01 is recorded as `.100` in previous tests and `.101` in another snapshot. Document the current address using `ipconfig` instead of claiming a single permanent lease.
4. **[LAB]** Treat DMZ as a logical lab segment; no separate DMZ server is claimed. Do not silently add a fictitious service to the documentation.

\* [LAB] The exact mask of the SECURITY interface still needs a current configuration export to independently verify the `/24` value.

![OPNsense overview](screenshots/opnsense-overview.png)

## 2. DHCP and DNS services

1. **[LAB]** KEA DHCP was enabled for configured client networks. Earlier interface bind conflicts on SERVERS/em3 (`10.10.30.1:67`) and DMZ/em4 (`10.10.40.1:67`) were resolved; `dnsmasq` was turned off to avoid competing port-67 listeners.
2. **[LAB]** Check **Services → KEA DHCP** for correct subnets, gateway options and leases. Do not copy a lease pool from this document: **<!-- TODO: export exact ranges, reservations and DNS option values. -->**
3. **[LAB]** Use DC01 `10.10.30.10` as the domain DNS server for Windows domain clients. WIN01 queries may appear to Unbound as DC01-originated because of the resolver/forwarding path; do not use this to infer the original workstation without corresponding client-side records.
4. **[LAB]** Review **Services → Unbound DNS** for resolver behavior and blocklist settings. Its observed blacklist verification surface is **Reporting → Unbound DNS → Details**. **<!-- TODO: provide blocklist source URLs and update schedule. -->**

### Verify DHCP/DNS

```powershell
# On WIN01 (read-only)
ipconfig /all
Resolve-DnsName corp.local -Server 10.10.30.10
```

```bash
# On Kali (lab read-only checks)
ip route
dig @10.10.30.10 corp.local A +short
dig @10.10.50.1 example.invalid A +noall +comments
```

[LAB] A successful domain lookup confirms a DNS response for this test; a failure points toward routing, DNS service or policy and is not evidence of a malicious event.

## 3. Firewall rule separation

[LAB] Firewall policies separate USERS, SERVERS, SECURITY and management traffic. Document each interface rule **in actual evaluation order** and distinguish `PASS` from `BLOCK` in filterlog. The complete ordered policy export was not supplied; therefore this guide lists only rules previously identified by name:

| Zone | Known rule name | Confirmed scope |
|---|---|---|
| USERS / em2 | [LAB] `AEGIS TI - Malicious IP Block` | [LAB] Dedicated policy for the zone; exact UUID and match fields require export |
| SERVERS / em3 | [LAB] `AEGIS TI - DC01 Malicious IP Block` | [LAB] Dedicated DC01/servers policy; exact UUID requires export |
| SECURITY / em5 | [LAB] `AEGIS TI - Kali Malicious IP Block` | [LAB] Ingress block for Kali-to-test-IP TCP/443 and ICMP confirmed in Live View |

[KOD] The SOC does not infer a TI block from `BLOCK` alone. It relates the OPNsense filterlog rule UUID to an approved reference register. [LAB] The confirmed test event was `10.10.50.100 → 198.51.100.77` on SECURITY/em5, ingress, for TCP and ICMP; `198.51.100.77` is a documentation/test address, not a proven malicious host.

![Firewall log evidence](screenshots/opnsense-firewall-liveview.png)

### Validate firewall policy

1. **[LAB]** Open **Firewall → Log Files → Live View** and filter for `10.10.50.100` or `198.51.100.77`.
2. **[LAB]** Inspect **interface**, **direction**, **action**, **source/destination** and **rule**; only call it a TI-policy block when the rule identity matches the approved PF rule entry.
3. **[KOD]** In AEGIS, query `/api/events?mode=all&source=FIREWALL&limit=100` and inspect `parsed.action` and original evidence. A `BLOCK` alone cannot prove blacklist attribution.
4. **[LAB]** Example benign denied traffic in historical logs included USERS to DC01 UDP/123 and DC01 `.255` NetBIOS broadcast; do not score these as high-risk attacks by default.

## 4. Suricata IDS observation

1. **[LAB]** Suricata operated in the lab with ET Open and additional observed signatures, including `KALI SECURITY TEST`, GPL ICMP PING and Nmap-related signatures. **<!-- TODO: export installed rulesets, enabled categories, versions and IDS vs IPS mode. -->**
2. **[LAB]** Generate only authorized lab traffic from Kali to DC01; previously observed ports included DNS `53`, Kerberos `88`, RPC `135`, LDAP `389`, SMB `445`, and restricted RDP `3389`.
3. **[KOD]** The parser reads EVE JSON attributes including `alert.signature`, `signature_id`, severity, flow identifiers, direction, and addresses when present.
4. **[KOD]** Severity mapping uses Suricata levels 1 → critical, 2 → high and 3 → medium; `KALI SECURITY TEST` is deliberately downgraded to low as a known lab signature.

![Network detections](screenshots/soc-network-detail.png)

### Verify Suricata

```bash
# From an authorized Kali lab VM only
nmap -sS -Pn -n -p 53,88,135,389,445 --max-retries 1 10.10.30.10
```

[LAB] Check the corresponding **Suricata alerts** and filterlog records. [KOD] The collector must forward the resulting EVE records to SOC; a single Nmap run can produce zero or many signatures depending on enabled rules, filtering and network placement.

## 5. Remote syslog / collector

1. **[LAB]** Firewall, DNS and Suricata remote logging had been directed to Kali `10.10.50.100`, with UDP syslog on port `514` observed for the logging pipeline.
2. **[LAB]** Kali rsyslog was used to split input into `/var/log/opnsense/firewall.log`, `/var/log/opnsense/dns.log` and `/var/log/opnsense/suricata.log`; the collector was also observed under `/opt/ad-opnsense-soc/collector.py`.
3. **[LAB]** Some later lab sessions used `aegis-collector.service` and `aegis-dns-reader.timer`. These service names are deployment evidence—not files shipped by the documented Python application. [KOD] The public code snapshot does not contain the complete Kali collector implementation.
4. **[KOD]** AEGIS receives collector output via authenticated-when-configured `POST /api/events/ingest`; it should not be described as remotely changing firewall configuration.

### Verify end to end

```bash
# Kali: observe the existing deployment, do not create duplicate collectors
sudo systemctl status rsyslog --no-pager
sudo systemctl status aegis-collector.service --no-pager
sudo ss -ulnp | grep ':514' || true
sudo tail -n 5 /var/log/opnsense/firewall.log
```

```powershell
# SOC host
Invoke-RestMethod 'http://127.0.0.1:8088/api/events?mode=all&source=FIREWALL,SURICATA,DNS&limit=20'
Invoke-RestMethod 'http://127.0.0.1:8088/api/source-health'
```

[LAB] Success means a recent sensor-side event can be tied to a matching SOC record by event time, address, action and signature—not merely that the API responds with HTTP 200.

## Configuration evidence still needed for a byte-for-byte rebuild

<!-- TODO: OPNsense build/version, interface-to-WAN mapping and exact network masks -->
<!-- TODO: export ordered PF rules and alias definitions with rule UUIDs -->
<!-- TODO: DHCP pools, DNS forwarders, Unbound blocklist source/update configuration -->
<!-- TODO: Suricata mode, interface assignments and enabled rule files -->
<!-- TODO: rsyslog UDP forwarding facility/category mappings -->
