import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Function to generate a random AES key
def generate_key():
    return os.urandom(32)  # 256-bit key

# Task 2.1: Encrypt a file using AES in CBC mode
def encrypt_file(file_path, key, iv):
    # Read the file contents
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Apply PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Write the ciphertext to a file
    with open('encrypted_sample.bin', 'wb') as f:
        f.write(ciphertext)

# Task 2.2: Decrypt a file using AES in CBC mode
def decrypt_file(encrypted_file_path, key, iv):
    # Read the encrypted contents
    with open(encrypted_file_path, 'rb') as f:
        ciphertext = f.read()

    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Write the plaintext to a file
    with open('decrypted_sample.txt', 'wb') as f:
        f.write(plaintext)

# Main function to perform encryption and decryption
def main():
    # Generate a random AES key and IV
    key = generate_key()
    iv = os.urandom(16)  # AES block size is 16 bytes

    # Task 2.1: Encrypt the file
    print("Encrypting the file...")
    encrypt_file('sample.txt', key, iv)
    print("File encrypted as 'encrypted_sample.bin'.")

    # Task 2.2: Decrypt the file
    print("Decrypting the file...")
    decrypt_file('encrypted_sample.bin', key, iv)
    print("File decrypted as 'decrypted_sample.txt'.")

    # Verify the result
    with open('sample.txt', 'rb') as original, open('decrypted_sample.txt', 'rb') as decrypted:
        if original.read() == decrypted.read():
            print("Decryption successful! The original and decrypted files match.")
        else:
            print("Decryption failed! The files do not match.")

if __name__ == '__main__':
    main()