import at.favre.lib.bytes.Bytes;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * Implements AES (Advanced Encryption Standard) with Galois/Counter Mode (GCM), which is a mode of
 * operation for symmetric key cryptographic block ciphers that has been widely adopted because of
 * its efficiency and performance.
 * The iv, encrypted content and auth tag will be encoded to the following format:
 * out = byte[] {x y y y y y y y y y y y y z z z ...}
 * x = IV length as byte
 * y = IV bytes
 * z = content bytes (encrypted content)
 */

public class AesGcmEncryption implements AuthenticatedEncryption {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    private final SecureRandom secureRandom;
    private ThreadLocal<Cipher> cipherWrapper = new ThreadLocal<>();

    public AesGcmEncryption() {
        this(new SecureRandom());
    }

    public AesGcmEncryption(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    public byte[] encrypt(String rawEncryptionKey, byte[] rawData) throws AuthenticatedEncryptionException {
        if (rawEncryptionKey.getBytes().length < 16) {
            throw new IllegalArgumentException("key length must be longer than 16 bytes");
        }
        byte[] iv = null;
        byte[] encrypted = null;
        try {
            iv = new byte[IV_LENGTH_BYTE];
            secureRandom.nextBytes(iv);

            final Cipher cipherEnc = getCipher();
            cipherEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawEncryptionKey.getBytes(), "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            encrypted = cipherEnc.doFinal(rawData);

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encrypted.length);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);
            return byteBuffer.array();
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not encrypt", e);
        } finally {
            Bytes.wrap(iv).mutable().secureWipe();
            Bytes.wrap(encrypted).mutable().secureWipe();
        }
    }


    @Override
    public byte[] decrypt(String rawEncryptionKey, byte[] encryptedData) throws AuthenticatedEncryptionException {
        byte[] iv = null;
        byte[] encrypted = null;
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

            int ivLength = byteBuffer.get();
            iv = new byte[ivLength];
            byteBuffer.get(iv);
            encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);

            final Cipher cipherDec = getCipher();
            cipherDec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawEncryptionKey.getBytes(), "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            return cipherDec.doFinal(encrypted);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not decrypt", e);
        } finally {
            Bytes.wrap(iv).mutable().secureWipe();
            Bytes.wrap(encrypted).mutable().secureWipe();
        }
    }

    @Override
    public int byteSizeLength(@KeyStrength int keyStrengthType) {
        return keyStrengthType == STRENGTH_HIGH ? 16 : 32;
    }

    private Cipher getCipher() {
        Cipher cipher = cipherWrapper.get();
        if (cipher == null) {
            try {
                cipher = Cipher.getInstance(ALGORITHM);
            } catch (Exception e) {
                throw new IllegalStateException("could not get cipher instance", e);
            }
            cipherWrapper.set(cipher);
            return cipherWrapper.get();
        } else {
            return cipher;
        }
    }
}
