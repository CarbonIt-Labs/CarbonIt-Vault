# CarbonIt Vault 🛡️

**Developed by Edwin Sam K Reju** | [CarbonIt Labs](https://github.com/CarbonIt-Labs/CarbonIt-Vault)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

CarbonIt Vault is a local-first, serverless desktop password manager engineered for ultimate sovereignty and post-quantum security. By combining a native desktop OS wrapper (`pywebview`) with NIST-standardized post-quantum key encapsulation (ML-KEM-1024), CarbonIt Vault protects your credentials against modern brute-force techniques as well as future quantum computing threats.

---

## 👨‍💻 Author & Lead Developer

**Edwin Sam K Reju**  
* Founder & Developer at CarbonIt Labs  
* GitHub Repository: [https://github.com/CarbonIt-Labs/CarbonIt-Vault](https://github.com/CarbonIt-Labs/CarbonIt-Vault)

---

## 🚀 Key Features

* **Post-Quantum Key Establishment:** Implements NIST-standardized **ML-KEM-1024** via QuantCrypt to ensure your vault keys remain secure even against quantum decryption.
* **Argon2id Key Derivation:** Uses memory-hard password hashing (Argon2id) to protect against modern GPU/ASIC brute-force attacks.
* **Zero-Trust Memory Management:** Actively zeroizes active symmetric keys using mutable `bytearray` objects in Python RAM the moment the vault is locked.
* **Authenticated Symmetric Encryption:** Secure local storage (`.civ`) using QuantCrypt Krypton authenticated encryption.

---

## 🔐 Security Architecture

CarbonIt Vault operates under a strict **zero-knowledge** local model:

1. **Password Hashing:** Argon2id processes your master password with a cryptographically secure 16-byte salt to yield a high-cost 64-byte `password_key`.
2. **KEM Encapsulation:** ML-KEM-1024 generates a public/private keypair and encapsulates a shared secret.
3. **Domain-Separated Key Derivation:** The final `vault_key` is established via SHA3-512 with strict domain separation:
   $$\text{vault\_key} = \text{SHA3-512}(\text{"CARBONIT-VAULT-V1|"} \parallel \text{password\_key} \parallel \text{pq\_shared\_secret})$$
4. **Encrypted Key Storage:** The ML-KEM secret key is encrypted with the password key using Krypton authenticated encryption.
5. **Session Token Authorization:** All Javascript-to-Python bridge calls are strictly verified using runtime session tokens injected by `pywebview`.

---

## 📦 Installation & Setup

### Prerequisites
* Python 3.10 or higher

### Steps

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/CarbonIt-Labs/CarbonIt-Vault.git
   cd CarbonIt-Vault
   ```

2. **Set Up Virtual Environment:**
   * **Windows:**
     ```cmd
     python -m venv .venv
     .venv\Scripts\activate
     ```
   * **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Running CarbonIt Vault

Launch the native desktop application:

```bash
python app.py
```

> **Note:** Ensure `app.py`, `app.js`, `index.html`, `style.css`, and `crypto.py` are all located within the root directory of the project.

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file or visit [Open Source Initiative](https://opensource.org/licenses/MIT) for full details.

Copyright (c) 2026 Edwin Sam K Reju
