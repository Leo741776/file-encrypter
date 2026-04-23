public class DES {
    private final long[] subkeys = new long[16];

    public DES(long key64) {
        KeySchedule ks = new KeySchedule(key64);
        System.arraycopy(ks.subkeys, 0, subkeys, 0, 16);
    }

    public long encryptBlock(long block) {
        return feistel(block, false);
    }

    public long decryptBlock(long block) {
        return feistel(block, true);
    }

    private long feistel(long block, boolean decrypt) {
        long ip = permute(block, DESTables.IP, 64);
        // & 0xFFFFFFFFL prevents sign extension when the int is promoted to long
        int L = (int) ((ip >>> 32) & 0xFFFFFFFFL);
        int R = (int) (ip & 0xFFFFFFFFL);

        for (int r = 0; r < 16; r++) {
            // Decryption applies the same rounds with subkeys in reverse order
            int subkeyIndex = decrypt ? 15 - r : r;
            int temp = L;
            L = R;
            R = temp ^ feistelF(R, subkeys[subkeyIndex]);
        }

        // DES requires L and R to be swapped before the final permutation
        long preOutput = ((long) R & 0xFFFFFFFFL) << 32 | ((long) L & 0xFFFFFFFFL);
        return permute(preOutput, DESTables.FP, 64);
    }

    private int feistelF(int R, long subkey48) {
        long eR = permute(R & 0xFFFFFFFFL, DESTables.E, 32);
        long x = eR ^ subkey48;
        int out = 0;
        for (int i = 0; i < 8; i++) {
            int sixBits = (int) ((x >>> (42 - 6 * i)) & 0x3F);
            // S-box row is formed by the outermost two bits (bits 5 and 0)
            int row = ((sixBits & 0x20) >>> 4) | (sixBits & 0x01);
            // S-box column is the four inner bits
            int col = (sixBits >>> 1) & 0x0F;
            out = (out << 4) | DESTables.SBOX[i][row][col];
        }
        return (int) (permute(out & 0xFFFFFFFFL, DESTables.P, 32) & 0xFFFFFFFFL);
    }

    private static long permute(long value, int[] table, int inWidth) {
        long out = 0L;
        for (int pos : table) {
            // Tables use 1-based bit positions from the left; convert to a right-shift offset
            int srcBit = inWidth - pos;
            out = (out << 1) | ((value >>> srcBit) & 1L);
        }
        return out;
    }

    static class KeySchedule {
        final long[] subkeys = new long[16];
        // Per-round left-rotation amounts mandated by the DES specification
        private static final int[] SHIFTS = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

        KeySchedule(long key64) {
            long pc1Out = DES.permute(key64, DESTables.PC1, 64);
            // & 0x0FFFFFFF masks to exactly 28 bits for each half-key
            int C = (int) ((pc1Out >>> 28) & 0x0FFFFFFF);
            int D = (int) (pc1Out & 0x0FFFFFFF);

            for (int i = 0; i < 16; i++) {
                C = leftRotate28(C, SHIFTS[i]);
                D = leftRotate28(D, SHIFTS[i]);
                subkeys[i] = DES.permute(((long) C << 28) | (long) D, DESTables.PC2, 56);
            }
        }

        private static int leftRotate28(int val, int n) {
            // Upper bits beyond position 28 are cleared to keep the half-key exactly 28 bits wide
            return ((val << n) | (val >>> (28 - n))) & 0x0FFFFFFF;
        }
    }
}