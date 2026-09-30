<div align="center">
  
  # 🛡️ CarbonIt Vault
  **The Sovereign, Post-Quantum Desktop Password Manager**
  <!-- Developer & Organization -->
  [![Developer](https://img.shields.io/badge/Developer-Edwin%20Sam%20K%20Reju-ffffff?labelColor=000000&logo=github&logoColor=white&style=for-the-badge)](https://edwinsamkreju.github.io/)
[![Organization](https://img.shields.io/badge/Organization-CarbonIt%20Labs-000000?labelColor=000000&logo=github&logoColor=00e5ff&style=for-the-badge)](https://github.com/CarbonIt-Labs)

<!-- Cryptography & Security Stack -->
![PQC Encryption](https://img.shields.io/badge/PQC-ML--KEM--1024%20%2F%20Kyber-7000ff?style=flat-square)
![Key Derivation](https://img.shields.io/badge/KDF-Argon2id-blue?style=flat-square)
![Symmetric Cipher](https://img.shields.io/badge/Cipher-QuantCrypt--Krypton-00e5ff?style=flat-square)
![Security Standard](https://img.shields.io/badge/Security-Post--Quantum%20Ready-00a9bd?style=flat-square)

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
  [![Built with pywebview](https://img.shields.io/badge/built%20with-pywebview-blue)](https://pywebview.flowrl.com/)

  *Developed by **Edwin Sam K Reju** at [CarbonIt Labs](https://github.com/CarbonIt-Labs)*
</div>

---

## 🚀 Overview

**CarbonIt Vault** is a local-first, serverless native desktop password manager engineered for ultimate data sovereignty and future-proof security. By combining a lightweight desktop OS wrapper with NIST-standardized post-quantum cryptography, CarbonIt Vault ensures your credentials are mathematically protected against both modern brute-force techniques and emerging quantum computing threats.

Your data never touches a cloud server. Your master password never leaves your RAM. You own your vault.

---

## ✨ Unrivaled Advantages

* 🛡️ **Post-Quantum Key Encapsulation:** Implements NIST-standardized **ML-KEM-1024** (via QuantCrypt) to generate keys that even future quantum computers cannot break.
* 🧠 **Zero-Trust Memory Hygiene:** Active RAM zeroization overwrites decrypted secrets and master passwords with null bytes the exact moment the vault is locked.
* 🛑 **Anti-Brute-Force Shield:** Integrates memory-hard Argon2id hashing alongside an active, time-based rate-limiting lockout mechanism to neutralize local attack vectors.
* 📦 **Sovereign Data Portability:** Seamlessly export, import, and backup your encrypted `.civ` (CarbonIt Vault) files across devices. 
* ⏱️ **Auto-Clearing Clipboard:** Passwords copied to your system clipboard are automatically wiped after 30 seconds.
* 🖥️ **Native Desktop Experience:** Built on `pywebview` for a seamless, borderless, native application feel across Windows, macOS, and Linux.

---

## 🔐 Cryptographic Architecture

CarbonIt Vault operates under a strict **zero-knowledge** local model:

1. **High-Cost Hashing:** Argon2id processes the master password with a 16-byte salt to yield a 64-byte `password_key`.
2. **KEM Encapsulation:** ML-KEM-1024 generates a public/private keypair and encapsulates a shared secret.
3. **Domain Separation:** The final `vault_key` is established via SHA3-512:
   `vault_key = SHA3-512("CARBONIT-VAULT-V1|" + password_key + pq_shared_secret)`
4. **Authenticated Encryption:** The vault contents and ML-KEM secret keys are encrypted using QuantCrypt Krypton authenticated symmetric encryption.
5. **Secure RPC Bridge:** UI-to-Python API calls are strictly verified using runtime-injected, cryptographically secure session tokens.

---

## ⚙️ Installation & Setup

### Prerequisites
* Python 3.10 or higher

### Developer Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/CarbonIt-Labs/CarbonIt-Vault.git
   cd CarbonIt-Vault
   ```

2. **Initialize Virtual Environment:**
   * **Windows:** `python -m venv .venv && .venv\Scripts\activate`
   * **Linux/macOS:** `python3 -m venv .venv && source .venv/bin/activate`

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch Application:**
   ```bash
   python app.py
   ```

---

## 🛠️ Production Build (Windows .exe)

To compile CarbonIt Vault into a single executable file with your custom icon:

```bash
pip install pyinstaller
pyinstaller --clean app.spec
```
*Your standalone desktop application will be generated in the `dist/` directory.*

---

## 📄 License & Credits

**Copyright (c) 2026 CarbonIt Labs | Edwin Sam K Reju**

This project is licensed under the [MIT License](LICENSE).
