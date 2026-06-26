# 🔐 VaultX

A secure, modern **C++17 password manager** that encrypts and stores user credentials locally using **AES-256-GCM**, **PBKDF2-HMAC-SHA256**, **OpenSSL**, and **SQLite3**.

VaultX demonstrates secure password storage, authenticated encryption, modern C++ object-oriented design, and database integration.

---

## ✨ Features

* Master Password protected vault
* PBKDF2-HMAC-SHA256 key derivation
* AES-256-GCM authenticated encryption
* SQLite3 local encrypted database
* Secure random password generator
* Search credentials
* Update credentials
* Delete credentials
* Secure session management
* Clean command-line interface
* Modular OOP architecture

---

## 🛡 Security

VaultX never stores plaintext passwords.

Each stored credential is encrypted using:

* AES-256-GCM
* Unique random IV for every credential
* Authentication Tag verification
* PBKDF2-HMAC-SHA256 derived master key
* Cryptographically secure random salt

Only encrypted data is written to disk.

---

## 🏗 Project Architecture

```
VaultX
│
├── include
│   ├── Crypto.h
│   ├── Database.h
│   └── PasswordManager.h
│
├── src
│   ├── main.cpp
│   ├── Crypto.cpp
│   ├── Database.cpp
│   └── PasswordManager.cpp
│
├── database
│   └── vault.db
│
├── CMakeLists.txt
└── README.md
```

---

## ⚙ Technologies

* C++17
* OpenSSL
* SQLite3
* CMake
* Ninja
* Object-Oriented Programming
* RAII

---

## 🔒 Cryptography

### Master Password

```
Master Password
        │
        ▼
PBKDF2-HMAC-SHA256
        │
        ▼
256-bit Encryption Key
```

---

### Password Storage

```
Password
      │
      ▼
AES-256-GCM
      │
      ▼
Ciphertext + IV + Authentication Tag
      │
      ▼
SQLite Database
```

---

## 🗄 Database Schema

### vault_config

| Column      | Description                 |
| ----------- | --------------------------- |
| master_hash | SHA-256 hash of derived key |
| salt        | Random PBKDF2 salt          |

### credentials

| Column       | Description                |
| ------------ | -------------------------- |
| id           | Primary key                |
| service_name | Website/Application        |
| account_name | Username/Email             |
| ciphertext   | Encrypted password         |
| iv           | Initialization Vector      |
| auth_tag     | AES-GCM authentication tag |

---

## 🚀 Build

```bash
cmake -S . -B build
cmake --build build
```

Run

```bash
./build/VaultX.exe
```

---

## 📋 Application Workflow

```
First Launch
        │
        ▼
Create Master Password
        │
        ▼
Vault Initialized
        │
        ▼
Unlock Vault
        │
        ▼
Add / View / Search / Update / Delete Credentials
        │
        ▼
Lock Vault
```

---

## 📚 Concepts Demonstrated

* Object-Oriented Programming
* Separation of Concerns
* RAII
* Cryptography
* Secure Password Storage
* Database Management
* File Persistence
* CLI Application Design
* Modern C++17

---

## 📌 Future Improvements

* Password strength meter
* Clipboard copy support
* Credential categories
* Password expiration reminders
* Import/Export encrypted vault
* Automatic database backup
* Cross-platform support
* GUI using Qt

---

## 📄 License

This project is intended for educational purposes and portfolio demonstration.
