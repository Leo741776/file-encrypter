# DES File Encrypter
This is a program that encrypts/decrypts any binary or text file (.txt, .png, .jpg, .mp3, .mov, etc.) using DES (the Data Encryption Standard).

## How to Run
- From the root directory, run: `mvn javafx:run` (must have Maven installed)
- When encrypting, **save the hex key somewhere**, it'll be used to decrypt the encrypted file afterwards

## Overview
- **UI Layer:** JavaFX GUI with mode selection (Encrypt/Decrypt), a file browser, and a hex key input. Validates that the key is exactly 16 hex characters (= 64-bit DES key). On decrypt, checks the file size is 8 + (n × 8) bytes (IV + whole blocks).
- **Key Generation:** Generates a random 64-bit key using SecureRandom and returns it as a 16-char uppercase hex string.
- **File Cipher:** Generates a random 64-bit key using SecureRandom and returns it as a 16-char uppercase hex string.
  - Encrypt: pads the file data with PKCS#7, generates a random 8-byte IV, then encrypts each 8-byte block in CBC mode (each plaintext block is XOR'd with the previous ciphertext block before encrypting). Output = [IV][ciphertext...].
  - Decrypt: reads the IV from the first 8 bytes, decrypts each block, XOR's with the previous ciphertext block, then strips the PKCS#7 padding
- **DES Core:** Implements the full FIPS 46-3 DES algorithm from scratch. Key schedule: derives 16 round subkeys (48-bit each) from the 64-bit key using PC-1/PC-2 permutations and per-round left rotations (defined in DESTables). Feistel network: 16-round cipher using expansion (E), XOR with subkey, S-box substitution, P-box permutation, wrapped in IP/FP permutations. Decryption is identical but subkeys are applied in reverse order.

## Screenshots
<p align="center">
  <img width="510" height="371" alt="Image" src="https://github.com/user-attachments/assets/8713271b-f034-4f31-9757-35e83693ab3a" />
  <img width="510" height="371" alt="Image" src="https://github.com/user-attachments/assets/9c85c2ca-0ccc-45f1-8724-2892653698cd" />
</p>