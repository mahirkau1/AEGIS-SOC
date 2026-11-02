# AEGIS SOC — screenshot index

[LAB] These screenshots were selected from the owner's November 2026 lab capture archive. They are **visual evidence of a configured laboratory**, not independently certified proof of a production deployment. They are embedded in the READMEs and deeper guides where relevant.

## Dashboard and investigation

| Screen | Purpose |
|---|---|
| ![SOC command center](soc-security-command-center.png) | [LAB] Security Command Center overview |
| ![Sysmon overview](sysmon-endpoint-overview.png) | [LAB] Endpoint · Sysmon investigation summary |
| ![Sysmon process detail](sysmon-process-investigation.png) | [LAB] Process relationship / suspicious process evidence |
| ![Sysmon analysis](sysmon-analysis-detail.png) | [LAB] Rule-level investigation context |
| ![Identity intelligence](identity-ad-intelligence.png) | [LAB] Identity · AD Intelligence |
| ![Identity behavior](identity-security-intelligence.png) | [LAB] Identity security investigation and context |
| ![Identity privilege](identity-privilege-memberships.png) | [LAB] Identity membership / privilege evidence |
| ![Lab map](network-lab-topology.png) | [LAB] Network laboratory topology |
| ![All logs](soc-all-logs.png) | [LAB] Centralized log investigation |

## OPNsense and network monitoring

| Screen | Purpose |
|---|---|
| ![OPNsense overview](opnsense-overview.png) | [LAB] OPNsense status overview |
| ![Firewall logs](opnsense-firewall-liveview.png) | [LAB] Firewall Live View |
| ![Firewall detail](opnsense-firewall-log-detail.png) | [LAB] Log detail table |
| ![Policy](opnsense-rule-config.png) | [LAB] Configuration / rule context |
| ![Unbound](opnsense-unbound-monitoring.png) | [LAB] DNS/Unbound view |
| ![Network analysis](soc-network-detail.png) | [LAB] SOC network analysis details |
| ![Network evidence](soc-network-logs.png) | [LAB] SOC network event list |
| ![OPNsense overall](opnsense-dashboard-final.png) | [LAB] Another OPNsense overview capture |

## Active Directory and VM arrangement

| Screen | Purpose |
|---|---|
| ![OU](ad-ou-structure.png) | [LAB] CORP-Users departmental OU tree |
| ![Finance](ad-finance-ou.png) | [LAB] Finance group context |
| ![HR](ad-hr-ou.png) | [LAB] HR group context |
| ![IT](ad-it-ou.png) | [LAB] IT group context |
| ![Management](ad-management-ou.png) | [LAB] Management group context |
| ![Sales](ad-sales-ou.png) | [LAB] Sales group context |
| ![WIN01 network](virtualbox-win01-network.png) | [LAB] WIN01 virtual NIC configuration |
| ![OPNsense network](virtualbox-opnsense-network.png) | [LAB] OPNsense virtual NIC configuration |
| ![DC01 network](virtualbox-dc01-network.png) | [LAB] DC01 virtual NIC configuration |
| ![Kali network](virtualbox-kali-network.png) | [LAB] Kali virtual NIC configuration |

## Publication review

[LAB] Screenshots may show real lab usernames, private addresses, MAC addresses, machine names and dates. Before publication, inspect each file at full size for credentials, tokens, cookies, session IDs, hostnames that identify a real organization, or personally sensitive text. If any appear, redact the **copy for publication** rather than removing source evidence from the private lab. Never publish raw Windows event XML or full OPNsense configuration backups without sanitizing them.

<!-- TODO: screenshot final privacy sign-off by repo owner -->
