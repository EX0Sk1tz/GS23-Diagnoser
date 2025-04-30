# 🛠 GS23 Diagnoser Tool

**GS23 Diagnoser** is a comprehensive diagnostic and support tool designed to help users and support staff quickly assess the compatibility and readiness of a Windows system for advanced software scenarios such as cheat loaders, modding tools, and other low-level applications.

It performs over 20 detailed system checks, reports compatibility issues, and provides actionable solutions. Ideal for use in support environments or by advanced users looking to fine-tune their system.

---

## 🔍 Features

- ✅ **Operating System Compatibility Check**
  - Supports Windows 10 (all builds) and Windows 11 up to **23H2**
  - Displays version status with clear color coding (green/red)

- 🛡️ **Security Checks**
  - UAC (User Account Control)
  - Antivirus (3rd-party and Defender)
  - Tamper Protection
  - Secure Boot
  - Memory Integrity (HVCI)
  - Virtualization (VT-x / AMD-V)
  - Test Mode
  - TPM (Trusted Platform Module)

- 🧱 **System Compatibility**
  - VC++ Runtimes presence
  - Boot Mode (UEFI / Legacy)
  - Overlay Conflict Detection (Steam, Discord, NZXT CAM, etc.)
  - Driver Signature Enforcement Status

- 🎮 **Anti-Cheat Detection**
  - Detects services and drivers from Vanguard, EAC, Battleye, FaceIt, etc.

- 💽 **HWID Integrity Check**
  - Disk serial
  - BIOS UUID
  - Motherboard serial
  - MAC address
  - 🧠 Outputs a **HWID Trust Score** to detect spoofing or tampering

- 📊 **Summary and Export**
  - Real-time log view and progress status
  - Export results to JSON or Clipboard
  - Send results via **Discord Webhook** for support tickets

- 💡 **Info & Help**
  - Professionally styled cards explaining each system check
  - Visual guides and step-by-step fixes

- 🛑 **Restore Point Creation**
  - Option to create a system restore point before making changes

---

## 📦 Installation

### Requirements
- **Windows 10** or **Windows 11 (up to 23H2)**
- Must be run as **Administrator**

### How to Launch
1. Download and extract the latest `.zip` release.
2. Run `GS23_Diagnoser.exe` as administrator (admin privileges are required for registry, driver, and system-level checks).

---

## 🚀 Usage

1. Click `🔍 Run Full Diagnostic` on the first tab.
2. Export or copy results to share or save.
3. Use the **Info & Help** tab to understand each check.
4. Optionally send diagnostics directly to a **Discord channel** using a webhook.

---

## 🌐 Links

- 🌍 [GS23 Services Website](https://gs23services.com)
- 📖 [Documentation (GitBook)](https://gs23.gitbook.io/gs23)
- 💬 [Community Discord](https://discord.gg/3bqHGasHXV)

---

## 📚 Screenshots

![GS23 Diagnoser 1](https://github.com/user-attachments/assets/ed13acb5-4abe-407d-b364-26d88d0161ef)
![GS23 Diagnoser 2jpg](https://github.com/user-attachments/assets/6064f8e3-3cf2-4211-b198-1dd6157bfc31)

---

## 🛠 Development & Contributions

This project is actively maintained by the GS23 Dev Team.  
At this time, public contributions are not open.

---

## 🔐 Disclaimer

This tool is designed for support and diagnostic purposes only.  
It **does not contain or distribute any cheat software** and should not be used in violation of software terms of service.

---

## 📅 Last Updated

April 2025
