# 🔒 C++ CLI Antivirus Scanner

A fast and lightweight antivirus engine written in modern C++ with support for:

- ✅ SHA256 hash-based signature matching
- ✅ YARA rule-based malware detection
- ✅ Entropy-based detection
- ✅ File quarantine with AES-GCM encryption
- ✅ File restore functionality

---

## ⚙️ Features

| Feature        | Description                              |
| -------------- | ---------------------------------------- |
| 🔍 Hash Scan   | Detect known malware using SHA256 hashes |
| 🧠 YARA Engine | Match complex malware using YARA rules   |
| 🗃️ Quarantine  | Encrypted storage of detected threats    |
| ♻️ Restore     | Restore and decrypt quarantined files    |

| yara rules compiled in signature folder. source: https://github.com/Yara-Rules/rules
| yara structure : https://github.com/VirusTotal/yara

---

## 🚀 Getting Started

### 🔧 Prerequisites

- C++17+
- YARA (libyara)
- OpenSSL
- Linux/macOS/Windows

> On Debian/Ubuntu:

```bash
sudo apt install libyara-dev libssl-dev build-essential
```
