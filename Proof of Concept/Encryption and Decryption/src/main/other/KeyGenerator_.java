import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public abstract class KeyGenerator_ {

    private static KeyGenerator single_instance = null;
    private SecureRandom secureRandom;
    private static SecretKey secretKey;
    private static byte[] initialVector;

    public abstract SecretKeySpec getSecretKey();

    public abstract byte[] getInitialVector();

}
