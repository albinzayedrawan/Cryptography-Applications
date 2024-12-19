# Cryptography Applications

## Overview

This project demonstrates the use of RSA and AES encryption algorithms for securing files. It includes two main scripts: rsa.py and aes.py.

The rsa.py script handles RSA key generation, encryption, and decryption, as well as hybrid encryption combining RSA and AES.

The aes.py script handles AES encryption and decryption.

## Files

**1. Asymmetric File Encryption (RSA):**

Contains functions for RSA key generation, RSA encryption/decryption, and hybrid encryption/decryption.

**2. Symmetric File Encryption (AES):**

Contains functions for AES encryption and decryption.

## Requirements

- Python 3.x
- cryptography library

You can install the required library using pip:

```sh
pip install cryptography
```

## Usage

### RSA Encryption and Decryption

1. **Generate RSA Keys**: The generate_rsa_keys function generates a pair of RSA keys (private and public).
2. **Save RSA Keys**: The save_rsa_keys function saves the generated RSA keys to files (private_key.pem and public_key.pem).
3. **Encrypt a File**: The rsa_encrypt_file function encrypts a file using the RSA public key.
4. **Decrypt a File**: The rsa_decrypt_file function decrypts a file using the RSA private key.

### Hybrid Encryption and Decryption (RSA + AES)

1. **Hybrid Encrypt a File**: The hybrid_encrypt function encrypts a file using AES and then encrypts the AES key using the RSA public key.
2. **Hybrid Decrypt a File**: The hybrid_decrypt function decrypts the AES key using the RSA private key and then decrypts the file using the AES key.

### AES Encryption and Decryption

1. **Generate AES Key**: The generate_key function generates a random 256-bit AES key.
2. **Encrypt a File**: The encrypt_file function encrypts a file using AES in CBC mode.
3. **Decrypt a File**: The decrypt_file function decrypts a file using AES in CBC mode.

## Running the Scripts

### rsa.py

To run the rsa.py script, execute the following command:

```sh
python rsa.py
```

This will perform the following tasks:

- Generate RSA keys and save them to files.
- Encrypt and decrypt a sample file (`sample.txt`) using RSA.
- Perform hybrid encryption and decryption on the sample file.

### aes.py

To run the aes.py script, execute the following command:

```sh
python aes.py
```

This will perform the following tasks:

- Generate a random AES key and IV.
- Encrypt and decrypt a sample file (`sample.txt`) using AES.

## Sample Files

- `sample.txt`: The sample file used for encryption and decryption.
- `rsa_encrypted_sample.bin`: The RSA encrypted file.
- `rsa_decrypted_sample.txt`: The RSA decrypted file.
- `hybrid_encrypted.bin`: The hybrid encrypted file.
- `hybrid_decrypted_sample.txt`: The hybrid decrypted file.
- `encrypted_sample.bin`: The AES encrypted file.
- `decrypted_sample.txt`: The AES decrypted file.

## Notes

- Ensure that the `sample.txt` file exists in the same directory as the scripts before running them.
- The scripts will generate and save the encrypted and decrypted files in the same directory.
