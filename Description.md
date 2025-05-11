# DES332MiniProject
Python code of a mini project for DES332 Group members: 6522781218, 6522772662, 6522790268

**Prerequisites:**
1. pycryptodrome
2. dropbox

**Prerequisite installation:** pip install dropbox pycryptodrome

**Description**
A Python-based tool that encrypts files locally before uploading them to Dropbox, ensuring end-to-end privacy. Uses AES-256 encryption for file contents and filenames, with keys derived from your password.

**Features**
1. Military-grade encryption: Files encrypted with AES-CBC (content) and AES-ECB (filenames).
2. Zero-knowledge design: Keys are derived from your password + salt—never stored or sent to Dropbox.
3. Tamper-proof: Includes IV validation, PKCS7 padding checks, and detailed error diagnostics.
4. Simple CLI menu: Upload, download, or delete files with a few keystrokes.

**How It Works**
- Derive keys using PBKDF2-SHA256 (100,000 iterations).
- Encrypt files: Scramble filenames and pad/file contents before upload.
- Decrypt securely: Auto-detect corruption, invalid passwords, or padding errors.

**How to operate**
This program can be run using vscode or Command Prompt or Terminal.
1. Enter a password (For encryption and decryption)
2. Enter Dropbox access token (Copy from Dropbox "App Console")
3. Select operation you want to complete

**Use Cases**
1. Store sensitive documents (tax files, contracts) in the cloud safely.
2. Prevent cloud providers (or hackers) from viewing filenames or content.
3. Educational example of applied cryptography with Python.
