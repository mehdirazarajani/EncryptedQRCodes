import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class KeyGenerator {

    private static KeyGenerator single_instance = null;
    private SecureRandom secureRandom;
    private static SecretKey secretKey;
    private static byte[] initialVector;

    private KeyGenerator() {
        secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        secretKey = new SecretKeySpec(key, "AES");
        initialVector = new byte[12];
        secureRandom.nextBytes(initialVector);
    }

    public static SecretKey getSecretKey() {
        if (single_instance == null)
            single_instance = new KeyGenerator();

        return secretKey;
    }

    public static byte[] getInitialVector() {
        if (single_instance == null)
            single_instance = new KeyGenerator();

        return initialVector;
    }
}
