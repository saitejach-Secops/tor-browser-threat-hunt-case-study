<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management..

- [Scenario Creation](https://github.com/saitejach-Secops/tor-browser-threat-hunt-case-study/blob/main/threat-hunting-scenario-tor-event-creation.md)

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or TOR-related file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and found TOR-related file activity on device `sai-md-threat-h` under the user `eaglebyte_0001`. The results showed TOR-related files being copied to the Desktop and the creation of a file named `tor-shopping-list.txt` on the Desktop at `2026-02-08T17:25:26.2662349Z`. These events began at `2026-02-08T16:59:31.437823Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where  DeviceName == "sai-md-threat-h"
| where InitiatingProcessAccountName == "eaglebyte_0001"
| where Timestamp >= datetime(2026-02-08T16:59:31.437823Z)
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, account=InitiatingProcessAccountName
```

<img width="1470" height="457" alt="image 1" src="https://github.com/user-attachments/assets/0fe6f600-71d8-4f50-8fa9-fa75f3479c6f" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string `tor-browser-windows-x86_64-portable-15.0.5.exe`. Based on the logs returned, at `2026-02-08T17:04:18.6716349Z`, the user `eaglebyte_0001` on the device `sai-md-threat-h` ran the file `tor-browser-windows-x86_64-portable-15.0.5.exe` from their Downloads folder using the `/s` parameter, which indicates a silent installation. The file hash recorded was `15448e951583b624c3f8fdfa8bc55fa9b65e1bcafd474f3f2dfd5444e4178846`.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where  DeviceName == "sai-md-threat-h"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.5.exe"
| project Timestamp, DeviceName, ActionType,FileName,FolderPath,SHA256,ProcessCommandLine,AccountName

```
<img width="1878" height="202" alt="image 2" src="https://github.com/user-attachments/assets/d440e205-eaf7-4e82-a048-84153af6dc2f" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user `eaglebyte_0001` actually opened the TOR browser. There was evidence that the browser was launched at `2026-02-08T17:06:00.6217017Z`. The `firefox.exe` process started from `C:\Users\eaglebyte_0001\Desktop\Tor Browser\Browser\firefox.exe`, and multiple `tor.exe` processes were spawned afterwards, confirming browser execution.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "sai-md-threat-h"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, ActionType,FileName,FolderPath,SHA256,ProcessCommandLine,AccountName
| order by Timestamp desc
```

<img width="1873" height="732" alt="image 3" src="https://github.com/user-attachments/assets/56416b47-c2bb-4d85-8b41-1953a760f3c7" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-02-08T17:06:08.7521622Z`, the user `eaglebyte_0001` successfully established a connection to the local address `127.0.0.1` on port `9151`, and the connection was initiated by `firefox.exe` running from `C:\Users\eaglebyte_0001\Desktop\Tor Browser\Browser\firefox.exe`. There were also additional connections to sites over port `443`, which supports active TOR browser usage.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "sai-md-threat-h"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe","firefox.exe")
| where RemotePort in ("9001","9030","9040","9050","9051","9150","9151","80","443")
| project Timestamp,ActionType,RemoteIP,RemotePort,RemoteUrl,InitiatingProcessAccountName,InitiatingProcessFileName,InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1662" height="515" alt="image 4" src="https://github.com/user-attachments/assets/a19e7228-fa1a-4fdb-ad08-80256e90f6c0" />

---

## Chronological Event Timeline

### 1. Initial Detection - TOR-Related File Activity

- **Timestamp:** `2026-02-08T16:59:31.437823Z`
- **Event:** The first TOR-related file activity was detected on device `sai-md-threat-h` under user `eaglebyte_0001`.
- **Action:** TOR-related file event detected.
- **File Path:** `C:\Users\eaglebyte_0001\`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-08T17:04:18.6716349Z`
- **Event:** The user `eaglebyte_0001` executed the file `tor-browser-windows-x86_64-portable-15.0.5.exe` in silent mode, initiating installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.5.exe /s`
- **File Path:** `C:\Users\eaglebyte_0001\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-08T17:06:00.6217017Z`
- **Event:** User `eaglebyte_0001` launched the TOR browser. The `firefox.exe` process started from the TOR Browser directory, and multiple `tor.exe` processes followed.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\eaglebyte_0001\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-08T17:06:08.7521622Z`
- **Event:** A network connection to `127.0.0.1` on port `9151` was established by `firefox.exe`, confirming communication with the TOR local proxy.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **File Path:** `C:\Users\eaglebyte_0001\Desktop\Tor Browser\Browser\firefox.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-02-08T17:06:08.7521622Z` - Local connection to `127.0.0.1` on port `9151`
  - Additional outbound connections observed over port `443`
- **Event:** Additional TOR-related network connections were observed, indicating continued browser activity through the TOR session.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-02-08T17:25:26.2662349Z`
- **Event:** The user `eaglebyte_0001` created a file named `tor-shopping-list.txt` on the Desktop.
- **Action:** File creation detected.
- **File Path:** `C:\Users\eaglebyte_0001\Desktop\tor-shopping-list.txt`

---

## Summary

The user `eaglebyte_0001` on endpoint `sai-md-threat-h` installed and used TOR Browser version `15.0.5`. The investigation showed TOR-related file activity, silent execution of the installer from the Downloads folder, launch of the browser through `firefox.exe`, and successful connection to the local TOR SOCKS proxy on port `9151`. Additional outbound connections over port `443` were also observed during the same session. A file named `tor-shopping-list.txt` was later created on the Desktop, showing user activity after the browser was launched. The full sequence took place within roughly 26 minutes and confirmed active TOR usage on the device.

---
## Analyst Assessment

The activity on `sai-md-threat-h` shows more than a simple file download. The telemetry confirms that the TOR Browser installer was executed with the `/s` parameter, which indicates a silent installation. Shortly after installation, `firefox.exe` launched from the TOR Browser directory and multiple `tor.exe` processes were created, showing that the browser was actively used rather than only installed.

Network telemetry further supports this assessment. A successful connection to `127.0.0.1:9151` was recorded, which aligns with TOR local proxy communication, and additional outbound connections over port `443` were observed during the same session. The later creation of `tor-shopping-list.txt` on the Desktop suggests follow-on user activity after the browser was launched.

Taken together, the file, process, and network evidence confirms deliberate installation and active TOR usage on the endpoint.

---
## Indicators of Compromise

- **Device Name:** `sai-md-threat-h`
- **User Account:** `eaglebyte_0001`
- **Installer File:** `tor-browser-windows-x86_64-portable-15.0.5.exe`
- **SHA-256:** `15448e951583b624c3f8fdfa8bc55fa9b65e1bcafd474f3f2dfd5444e4178846`
- **Processes Observed:** `firefox.exe`, `tor.exe`
- **TOR Proxy Port:** `9151`
- **User-Created File:** `tor-shopping-list.txt`
- **Installation Path:** `C:\Users\eaglebyte_0001\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`
- **Execution Path:** `C:\Users\eaglebyte_0001\Desktop\Tor Browser\Browser\firefox.exe`

---
## Detection Opportunities

- Alert on execution of TOR installers from user download directories.
- Alert on silent installation parameters such as `/s` when associated with browser or anonymisation tools.
- Monitor for `firefox.exe` or `tor.exe` launching from non-standard user directories such as the Desktop.
- Correlate TOR-related process execution with local proxy communication over port `9151`.
- Investigate systems where TOR-related file, process, and network events occur within the same activity window.

---
## Skills Demonstrated

- Threat hunting using Microsoft Defender for Endpoint.
- KQL query development.
- File, process, and network telemetry analysis.
- Timeline reconstruction.
- IOC identification.
- Incident triage and containment support.
---

## Response Taken

TOR usage was confirmed on the endpoint `sai-md-threat-h` by the user `eaglebyte_0001`. The device was isolated, and management was notified.

---
