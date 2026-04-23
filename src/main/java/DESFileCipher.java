import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

public class DESFileCipher {

    public static void process(String mode, String inputPath, String hexKey, String outputPath) throws Exception {
        Path inPath = Paths.get(inputPath);
        Path outPath = Paths.get(outputPath);
        byte[] fileData = Files.readAllBytes(inPath);
        long key64 = parseHexKey64(hexKey);

        if ("encrypt".equalsIgnoreCase(mode)) {
            Files.write(outPath, encrypt(fileData, key64));
        } else if ("decrypt".equalsIgnoreCase(mode)) {
            Files.write(outPath, decrypt(fileData, key64));
        } else {
            throw new IllegalArgumentException("Mode must be 'encrypt' or 'decrypt'.");
        }
    }

    private static long parseHexKey64(String hex) {
        if (hex.length() != 16) {
            throw new IllegalArgumentException("Key must be 16 hex chars (64 bits).");
        }
        return Long.parseUnsignedLong(hex, 16);
    }

    private static byte[] encrypt(byte[] input, long key64) {
        byte[] padded = pkcs7Pad(input, 8);
        byte[] iv = new byte[8];
        // A fresh random IV per encryption ensures identical plaintexts produce different ciphertexts
        new SecureRandom().nextBytes(iv);
        DES des = new DES(key64);
        // Output layout: [8-byte IV][ciphertext blocks]
        byte[] out = new byte[8 + padded.length];
        System.arraycopy(iv, 0, out, 0, 8);
        long prev = bytesToLong(iv, 0);
        for (int i = 0; i < padded.length; i += 8) {
            // CBC: XOR plaintext block with previous ciphertext block before encrypting
            long encrypted = des.encryptBlock(bytesToLong(padded, i) ^ prev);
            longToBytes(encrypted, out, 8 + i);
            prev = encrypted;
        }
        return out;
    }

    private static byte[] decrypt(byte[] input, long key64) {
        if (input.length < 8 || (input.length - 8) % 8 != 0) {
            throw new IllegalArgumentException("Invalid ciphertext length.");
        }
        DES des = new DES(key64);
        byte[] out = new byte[input.length - 8];
        // First 8 bytes are the IV, which seeds the CBC XOR chain
        long prev = bytesToLong(input, 0);
        for (int i = 0; i < out.length; i += 8) {
            long block = bytesToLong(input, 8 + i);
            longToBytes(des.decryptBlock(block) ^ prev, out, i);
            prev = block;
        }
        return pkcs7Unpad(out, 8);
    }

    private static byte[] pkcs7Pad(byte[] data, int blockSize) {
        int pad = blockSize - (data.length % blockSize);
        // PKCS#7 always adds at least one byte of padding so unpadding is unambiguous
        if (pad == 0) pad = blockSize;
        byte[] out = Arrays.copyOf(data, data.length + pad);
        for (int i = data.length; i < out.length; i++) {
            out[i] = (byte) pad;
        }
        return out;
    }

    private static byte[] pkcs7Unpad(byte[] data, int blockSize) {
        if (data.length == 0 || data.length % blockSize != 0) {
            throw new IllegalArgumentException("Invalid padded data length.");
        }
        int pad = data[data.length - 1] & 0xFF;
        if (pad < 1 || pad > blockSize)
            throw new IllegalArgumentException("Decryption failed: padding value " + pad + " is out of range — the key is likely wrong or the file is corrupted.");
        for (int i = 1; i <= pad; i++) {
            if ((data[data.length - i] & 0xFF) != pad)
                throw new IllegalArgumentException("Decryption failed: padding bytes are inconsistent — the key is likely wrong or the file is corrupted.");
        }
        return Arrays.copyOf(data, data.length - pad);
    }

    private static long bytesToLong(byte[] a, int off) {
        // & 0xFFL prevents sign extension when each byte is promoted to long
        return ((a[off]     & 0xFFL) << 56) | ((a[off + 1] & 0xFFL) << 48) |
               ((a[off + 2] & 0xFFL) << 40) | ((a[off + 3] & 0xFFL) << 32) |
               ((a[off + 4] & 0xFFL) << 24) | ((a[off + 5] & 0xFFL) << 16) |
               ((a[off + 6] & 0xFFL) <<  8) |  (a[off + 7] & 0xFFL);
    }

    private static void longToBytes(long v, byte[] out, int off) {
        // Big-endian: most significant byte first
        for (int i = 0; i < 8; i++) {
            out[off + i] = (byte) (v >>> (56 - (i * 8)));
        }
    }
}