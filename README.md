# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Edyth254/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "Yakayet2" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at `2025-06-16T05:49:03.0604384Z`. These events began at: `2025-06-16T04:47:48.8263755Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName startswith "Kayetvm"
| where InitiatingProcessAccountName startswith "Yakayet2"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-16T04:47:48.8263755Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/70ccfe42-4a04-4b27-957a-196406d1e128">
---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.3.exe". Based on the logs returned, at `2025-06-16T05:15:04.9741991Z`, the user Yakayet2 on the "Kayetvm" device ran the file `tor-browser-windows-x86_64-portable-14.5.3.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName startswith "Kayetvm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/ca297419-60ec-4772-a1bd-4604d94e7212">
---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "Yakayet2" actually opened the TOR browser. There was evidence that they did open it at `2025-06-16T05:17:22.6307847Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName startswith "Kayetvm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/677c3cd9-fec4-4a21-b3d0-bd61058f917e">
---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-06-16T05:18:01.7180715Z`, a user "Yakayet2" on the "Kayetvm" device successfully established a connection to the remote IP address `94.23.68.187` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\yakayet2\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName startswith "Kayetvm"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150" "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/134ccc3d-a6a7-436d-9f5c-3fa44502fb28">
---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-06-16T04:47:48.8263755Z`
- **Event:** The user "Yakayet2" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\yakayet2\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-06-16T05:15:04.9741991Z`
- **Event:** The user "Yakayet2" executed the file `tor-browser-windows-x86_64-portable-14.5.3.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`
- **File Path:** `C:\Users\yakayet2\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-06-16T05:17:22.6307847Z`
- **Event:** User "Yakayet2" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\yakayet2\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-06-16T05:18:01.7180715Z`
- **Event:** A network connection to IP `94.23.68.187` on port `9001` by user "Yakayet2" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\yakayet2\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-06-16T05:18:27.4105837Z` - Connection to `217.154.58.238` on port `443`.
  - `2025-06-16T05:17:58.6242676Z` - Connection to `131.188.40.189` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "Yakayet2" through the TOR browser.
- **Action:** Successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-06-16T05:49:03.0604384Z`
- **Event:** The user "Yakayet2" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\yakayet\Desktop\tor-shopping-list.txt`

---

## Summary

The user "Yakayet2" on the "Kayetvm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `Kayetvm` by the user `Yakayet2`. The device was isolated, and the user's direct manager was notified.

---
