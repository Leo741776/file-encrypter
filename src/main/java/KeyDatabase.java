import java.security.SecureRandom;

public class KeyDatabase {

    public static String generateRandomHexKey() {
        byte[] bytes = new byte[8];
        // SecureRandom instead of Random ensures the key cannot be predicted from the seed
        new SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder(16);
        for (byte b : bytes) {
            // %02X zero-pads single-digit bytes and uses uppercase hex to match the key field's expected format
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}