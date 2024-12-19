from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

# Task 3.1: Generate RSA key pair (2048-bit or higher)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Save RSA keys to files
def save_rsa_keys(private_key, public_key):
    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Encrypt a file using RSA public key
def rsa_encrypt_file(file_path, public_key):
    # Read the file contents
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Encrypt the file content with the RSA public key
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the encrypted content
    with open("rsa_encrypted_sample.bin", "wb") as f:
        f.write(ciphertext)

# Task 3.2: Decrypt a file using RSA private key
def rsa_decrypt_file(encrypted_file_path, private_key):
    # Read the encrypted content
    with open(encrypted_file_path, "rb") as f:
        ciphertext = f.read()

    # Decrypt the content with the RSA private key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the decrypted content
    with open("rsa_decrypted_sample.txt", "wb") as f:
        f.write(plaintext)

# Task 3.3: Hybrid Encryption: RSA + AES
def hybrid_encrypt(file_path, public_key):
    # Generate AES key and IV
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)  # AES block size

    # Encrypt the file using AES
    with open(file_path, "rb") as f:
        plaintext = f.read()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Encrypt AES key using RSA public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save encrypted AES key, IV, and ciphertext
    with open("hybrid_encrypted.bin", "wb") as f:
        f.write(encrypted_aes_key + iv + ciphertext)

# Hybrid Decryption: RSA + AES
def hybrid_decrypt(encrypted_file_path, private_key):
    # Read the encrypted file
    with open(encrypted_file_path, "rb") as f:
        data = f.read()

    # Extract encrypted AES key, IV, and ciphertext
    encrypted_aes_key = data[:256]  # RSA 2048-bit encryption produces 256-byte ciphertext
    iv = data[256:272]  # Next 16 bytes are the IV
    ciphertext = data[272:]  # Remaining bytes are the ciphertext

    # Decrypt the AES key using RSA private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the file using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Save the decrypted content
    with open("hybrid_decrypted_sample.txt", "wb") as f:
        f.write(plaintext)

# Main function
def main():
    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()
    save_rsa_keys(private_key, public_key)

    # Tasks 3.1 and 3.2: RSA Encryption and Decryption
    print("Performing RSA encryption and decryption...")
    rsa_encrypt_file("sample.txt", public_key)
    rsa_decrypt_file("rsa_encrypted_sample.bin", private_key)

    # Verify RSA decryption
    with open("sample.txt", "rb") as original, open("rsa_decrypted_sample.txt", "rb") as decrypted:
        assert original.read() == decrypted.read()
    print("RSA decryption successful!")

    # Task 3.3: Hybrid Encryption and Decryption
    print("Performing hybrid encryption and decryption...")
    hybrid_encrypt("sample.txt", public_key)
    hybrid_decrypt("hybrid_encrypted.bin", private_key)

    # Verify Hybrid decryption
    with open("sample.txt", "rb") as original, open("hybrid_decrypted_sample.txt", "rb") as decrypted:
        assert original.read() == decrypted.read()
    print("Hybrid decryption successful!")

if __name__ == "__main__":
    main()