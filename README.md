# Secure-File-Transfer-Tool-using-AES-CBC

## Overview
The **Secure File Transfer Tool (SFTT)** is a GUI-based application that enables secure file transfer between two systems using **AES-CBC encryption**. It ensures data privacy by encrypting files before transmission and decrypting them upon reception. The tool provides a simple yet effective user interface using **Tkinter** and supports real-time progress updates.

## Features
- 🔒 **AES-CBC Encrypted File Transfer**  
- 📡 **Send & Receive Modes**  
- 🌐 **Supports LAN & Internet Transfers**  
- 📊 **Real-Time Progress Tracking**  
- 🎛 **User-Friendly GUI with Tkinter**  
- 🔑 **Password-Based Encryption for Security**  
- ⚡ **Fast File Transmission with Chunking**  

## Requirements
Ensure you have the following dependencies installed:

```bash
pip install cryptography
```
```bash
pip install socket
```
```bash
pip install tkinter
```


## How to Use

### 1️⃣ **Run the Application**
Execute the script using:

```bash
python sftt.py
```

### 2️⃣ **Select Mode**
- **Send Mode:** Choose a file, enter the receiver’s IP and port, set a password, and click "Transfer".  
- **Receive Mode:** Enter a port and a matching password to listen for incoming files.

### 3️⃣ **Secure Transfer**
- The sender encrypts the file before transmission.  
- The receiver decrypts the file using the same password.  
- Progress updates are displayed during the process.

## Encryption Details
- **Algorithm:** AES (Advanced Encryption Standard)  
- **Mode:** CBC (Cipher Block Chaining)  
- **Key Derivation:** PBKDF2 with SHA-256
- **IV (Initialization Vector)**: Random IV for each encryption session to ensure uniqueness.
- **Salt:** Fixed (`b'sal_t'`) (Can be modified for improved security)  

## Notes
- Ensure both sender and receiver use the **same password** for encryption and decryption.  
- For external transfers, **port forwarding** may be required.  
- The file is encrypted **before** sending, so even if intercepted, it remains protected.

### Contact
For any issues, suggestions, or contributions, feel free to reach out or create an issue in the GitHub repository.
