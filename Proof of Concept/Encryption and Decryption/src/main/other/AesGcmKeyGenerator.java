import javax.crypto.spec.SecretKeySpec;

public class AesGcmKeyGenerator extends KeyGenerator_ {
    private AesGcmKeyGenerator(){
        super();

    }

    @Override
    public SecretKeySpec getSecretKey() {
        return null;
    }

    @Override
    public byte[] getInitialVector() {
        return new byte[0];
    }
}
