# Screenshot inventory

This gallery lists **all screenshots included in the documentation bundle**. The goal is to make it clear that the repository contains not just dashboard images, but also the **lab build evidence**: VirtualBox adapters, OPNsense pages, AD structure, Identity screens, SOC views and host/network validation snippets.

## 1. Virtual machine and network build evidence

| File | Description |
|---|---|
| `virtualbox-opnsense-network.png` | [LAB] VirtualBox network adapter view for the OPNsense VM. |
| `virtualbox-dc01-network.png` | [LAB] VirtualBox network adapter view for DC01. |
| `virtualbox-win01-network.png` | [LAB] VirtualBox network adapter view for WIN01. |
| `virtualbox-kali-network.png` | [LAB] VirtualBox network adapter view for Kali. |
| `network-lab-topology.png` | [LAB] Lab topology diagram/dashboard view showing main nodes and relationships. |
| `dc01-ipconfig.png` | [LAB] Windows IP configuration snippet from the domain controller side. |
| `kali-routing-table.png` | [LAB] Route table / interface validation on Kali. |

## 2. OPNsense build and validation

| File | Description |
|---|---|
| `opnsense-interface-assignments.png` | [LAB] Interface assignment/navigation view. |
| `opnsense-services-status.png` | [LAB] Service/status view used during firewall/DNS build validation. |
| `opnsense-overview.png` | [LAB] OPNsense overview page with system summary. |
| `opnsense-rule-config.png` | [LAB] Firewall rule configuration page. |
| `opnsense-firewall-liveview.png` | [LAB] Live firewall log view. |
| `opnsense-firewall-log-detail.png` | [LAB] Detailed firewall log entry view. |
| `opnsense-unbound-monitoring.png` | [LAB] Unbound monitoring/statistics page. |
| `opnsense-unbound-details.png` | [LAB] Additional Unbound/blocklist detail page. |
| `opnsense-dashboard-final.png` | [LAB] Final OPNsense dashboard / landing view. |

## 3. Active Directory structure

| File | Description |
|---|---|
| `ad-ou-structure.png` | [LAB] Top-level OU / group structure snapshot. |
| `ad-finance-ou.png` | [LAB] Finance OU and group membership view. |
| `ad-hr-ou.png` | [LAB] HR OU and group membership view. |
| `ad-it-ou.png` | [LAB] IT OU and group membership view. |
| `ad-management-ou.png` | [LAB] Management OU and group membership view. |
| `ad-sales-ou.png` | [LAB] Sales OU and group membership view. |

## 4. Identity and privilege analysis

| File | Description |
|---|---|
| `identity-ad-intelligence.png` | [KOD]/[LAB] Identity · AD Intelligence main workspace. |
| `identity-users-list.png` | [KOD]/[LAB] Identity users list. |
| `identity-security-intelligence.png` | [KOD]/[LAB] Identity security workspace. |
| `identity-privilege-memberships.png` | [KOD]/[LAB] Verified AD privilege/group membership view. |
| `identity-user360-profile.png` | [KOD]/[LAB] User360 profile-style view. |
| `identity-user360-risk-analysis.png` | [KOD]/[LAB] User360 risk-analysis view. |
| `soc-identity-user360-summary.png` | [KOD]/[LAB] Additional compact user summary card. |
| `soc-identity-details.png` | [KOD]/[LAB] Detailed identity evidence panel in the SOC. |

## 5. Sysmon and endpoint analysis

| File | Description |
|---|---|
| `sysmon-endpoint-overview.png` | [KOD]/[LAB] Endpoint · Sysmon landing page. |
| `sysmon-process-investigation.png` | [KOD]/[LAB] Process investigation view. |
| `sysmon-analysis-detail.png` | [KOD]/[LAB] Detail / AI-style analysis panel for a selected process event. |

## 6. SOC dashboard views

| File | Description |
|---|---|
| `soc-security-command-center.png` | [KOD]/[LAB] Main SOC command center. |
| `soc-all-logs.png` | [KOD]/[LAB] All Logs page. |
| `soc-network-detail.png` | [KOD]/[LAB] Network detection detail screen. |
| `soc-network-logs.png` | [KOD]/[LAB] Network log listing / evidence screen. |
| `soc-network-detection-summary.png` | [KOD]/[LAB] Supporting network summary table / compact detection evidence view. |
| `soc-cli-validation-output.png` | [LAB] CLI validation / terminal evidence snippet used during project verification. |

## 7. Quick gallery

### Virtualization and layout

![VirtualBox OPNsense](virtualbox-opnsense-network.png)
![VirtualBox DC01](virtualbox-dc01-network.png)
![VirtualBox WIN01](virtualbox-win01-network.png)
![VirtualBox Kali](virtualbox-kali-network.png)

### OPNsense

![Interfaces](opnsense-interface-assignments.png)
![Services](opnsense-services-status.png)
![Overview](opnsense-overview.png)
![Rules](opnsense-rule-config.png)
![Firewall live](opnsense-firewall-liveview.png)
![Firewall detail](opnsense-firewall-log-detail.png)
![Unbound monitoring](opnsense-unbound-monitoring.png)
![Unbound details](opnsense-unbound-details.png)
![OPNsense dashboard](opnsense-dashboard-final.png)

### Active Directory / Identity

![OU structure](ad-ou-structure.png)
![Finance](ad-finance-ou.png)
![HR](ad-hr-ou.png)
![IT](ad-it-ou.png)
![Management](ad-management-ou.png)
![Sales](ad-sales-ou.png)
![AD Intelligence](identity-ad-intelligence.png)
![Identity users](identity-users-list.png)
![Identity workspace](identity-security-intelligence.png)
![Privilege memberships](identity-privilege-memberships.png)
![User360 profile](identity-user360-profile.png)
![Risk analysis](identity-user360-risk-analysis.png)
![Identity summary](soc-identity-user360-summary.png)
![Identity details](soc-identity-details.png)

### SOC / Sysmon

![Sysmon overview](sysmon-endpoint-overview.png)
![Sysmon process investigation](sysmon-process-investigation.png)
![Sysmon detail](sysmon-analysis-detail.png)
![Command center](soc-security-command-center.png)
![All logs](soc-all-logs.png)
![Network detail](soc-network-detail.png)
![Network logs](soc-network-logs.png)
![Network summary](soc-network-detection-summary.png)
![CLI validation](soc-cli-validation-output.png)
