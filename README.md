# Windows Host Artifact & Command-and-Control (C2) Emulation Lab

## Overview
This repository documents a controlled laboratory research exercise focused on analyzing host-based artifacts, process behaviors, and command-and-control (C2) communication channels on a **Windows 10** environment. 

As an aspiring ethical hacker and penetration tester, understanding how payloads interact with the underlying operating system—and how those actions manifest in system logs and process trees—is critical for both offensive simulation and robust threat hunting.

---

## 🗺️MITRE ATT&CK Mapping
The lab simulation aligns with the following enterprise tactics and techniques:

| Tactics | Technique ID | Technique Name | Lab Observation |
| :--- | :--- | :--- | :--- |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Spawning of unauthorized shell instances (`cmd.exe`) via application handlers. |
| **Persistence** | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Evaluation of startup persistence mechanisms on Windows endpoints. |
| **Command & Control** | T1071.001 | Application Layer Protocol: Web Protocols | Outbound communication sessions utilizing standard web ports/protocols. |

---

## Key Forensic & Behavioral Findings

### 1. Process Tree Anomalies
* **Parent-Child Relationship Analysis:** During execution testing, legitimate utility boundaries were crossed when application processes spawned unexpected command interpreters (`cmd.exe` / `powershell.exe`).
* **Process Hollowing / Injections:** Monitored memory space allocations and suspicious thread creation flags within task managers and debugging utilities.

### 2. Windows Event Log Artifacts Generated
Key logs captured during the simulation phase that defenders look for:
* **Event ID 4688 (Security):** Detailed process creation logging, highlighting anomalous parent processes and command-line arguments.
* **Event ID 4625 / 4624 (Security):** Authentication tracking and session establishment logs.
* **Sysmon Event ID 1 (Process Creation):** High-fidelity tracking of process execution paths and hashes.

---

## Defensive Detection & Mitigation (Sigma Rule Example)
To demonstrate a comprehensive "Purple Team" mindset, every offensive simulation should be paired with a detection mechanism. Below is a sample **Sigma rule** designed to detect anomalous shell spawning behavior identified during this lab:

```yaml
title: Suspicious Child Process Spawned From Application Context
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects command shell execution spawned directly from user applications or document handlers.
references:
  - Internal Lab Research - Adversary Emulation
author: Mruga Gajjar
date: 2026/10/02
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\acrord32.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Legitimate administrative macros or automated enterprise update scripts.
level: high
