import sys
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Usage check
if len(sys.argv) != 2:
    script_name = os.path.basename(sys.argv[0])
    print(f"Usage: python {script_name} <input_file>")
    sys.exit(1)

input_file = sys.argv[1]

# Generate random 32-byte AES key
key = os.urandom(32)

# Use static IV (for testing)
iv = b"\x00" * 16

# Read binary input
with open(input_file, "rb") as f:
    data = f.read()

# Apply PKCS7 padding
padder = padding.PKCS7(128).padder()
padded_data = padder.update(data) + padder.finalize()

# AES-CBC encryption
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# Write encrypted binary
output_file = f"{input_file}_aes"
with open(output_file, "wb") as f:
    f.write(encrypted_data)
print(f"AES encrypted data written to: {output_file}")

# Write C++ header with encrypted payload and AES key
with open("payload.h", "w") as f:
    f.write("#pragma once\n")
    f.write("#include <windows.h>\n\n")

    # AES key
    f.write("unsigned char AES_KEY[32] = {\n")
    for i, b in enumerate(key):
        if i % 8 == 0:
            f.write("    ")
        f.write(f"0x{b:02x}")
        if i != 31:
            f.write(", ")
        if (i + 1) % 8 == 0:
            f.write("\n")
    f.write("};\n\n")

    # Payload
    f.write("BYTE payload[] = {\n")
    for i, b in enumerate(encrypted_data):
        if i % 12 == 0:
            f.write("    ")
        f.write(f"0x{b:02x}")
        if i != len(encrypted_data) - 1:
            f.write(", ")
        if (i + 1) % 12 == 0:
            f.write("\n")
    if len(encrypted_data) % 12 != 0:
        f.write("\n")
    f.write("};\n")
    f.write(f"DWORD payload_len = {len(encrypted_data)};\n")

print("C++ header file written to: payload.h")

