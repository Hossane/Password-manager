# Password-manager
A secure, local, command-line password manager built in Python. It encrypts your login credentials using cryptographic standards (AES-128 via Fernet) and stores them in a local SQLite database. Your master password is never stored in plaintext

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Cryptography](https://img.shields.io/badge/Cryptography-Fernet-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

- **Secure Encryption**: All passwords are encrypted with AES-128 using a key derived from your master password.
- **Master Password Protection**: The master password is hashed with `bcrypt` for secure verification.
- **Local Storage**: Your data is stored locally in an SQLite database; nothing is sent to the cloud.
- **CLI Interface**: Simple and intuitive text-based menu system.
- **Key Derivation**: Uses PBKDF2HMAC-SHA256 with a unique salt to generate encryption keys, protecting against brute-force attacks.
- **Full CRUD Operations**: Add, View, List, Edit, and Delete stored credentials easily.

---

## Built With

*   **Python 3**
*   **`cryptography`** (Fernet for encryption)
*   **`sqlite3`** (Database storage)
*   **`bcrypt`** (Master password hashing)
*   **`getpass`** (Secure password input)

---

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/YOUR_USERNAME/secure-password-manager.git
    cd secure-password-manager
    ```

2.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: The `cryptography` and `bcrypt` libraries are required. A `requirements.txt` file is included in the repo.)*

---

## Usage

1.  Run the script:
    ```bash
    python password_manager.py
    ```
2.  Set a strong master password on first launch.
3.  Use the menu to:
    - **Add** new service credentials.
    - **Retrieve** a stored password.
    - **List** all saved services.
    - **Edit** or **Delete** existing entries.

---

## Future Enhancements

*   Graphical User Interface (GUI) using Tkinter.
*   Export/import functionality for backups.

---

## ⚠️ Disclaimer

This software is created for **educational and portfolio purposes**. While it uses strong encryption, the author does not guarantee its absolute security for production use. Always practice good digital security hygiene.
