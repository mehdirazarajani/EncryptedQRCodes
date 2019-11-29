import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

/**
 * Implements AES (Advanced Encryption Standard) with Cipher Block Chaining (CBC), which is a mode of
 * operation for symmetric key cryptographic block ciphers. For integrity it uses HMAC with SHA-256,
 * using the encrypt-then-mac schema.
 * The iv, mac and encrypted content will be encoded to the following format:
 * out = byte[] {x y y y y y y y y y y y y i j j ... z z z ...}
     * x = IV length as byte
     * y = IV bytes
     * i = mac length as byte
     * j = mac bytes
     * z = content bytes (encrypted content, auth tag)
 */
final class AesCbcEncryption implements AuthenticatedEncryption {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int IV_LENGTH_BYTE = 16;

    private final SecureRandom secureRandom;
    private ThreadLocal<Cipher> cipherWrapper = new ThreadLocal<>();
    private Mac hmac;

    public AesCbcEncryption() {
        this(new SecureRandom());
    }

    public AesCbcEncryption(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    public byte[] encrypt(byte[] rawEncryptionKey, byte[] rawData) throws AuthenticatedEncryptionException {
        checkAesKey(rawEncryptionKey);

        byte[] iv = null;
        byte[] encrypted = null;
        byte[] mac = null;
        try {
            iv = new byte[IV_LENGTH_BYTE];
            secureRandom.nextBytes(iv);

            final Cipher cipherEnc = getCipher();
            cipherEnc.init(Cipher.ENCRYPT_MODE, createEncryptionKey(rawEncryptionKey), new IvParameterSpec(iv));
            encrypted = cipherEnc.doFinal(rawData);

            mac = macCipherText(rawEncryptionKey, encrypted, iv);

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + 1 + mac.length + encrypted.length);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put((byte) mac.length);
            byteBuffer.put(mac);
            byteBuffer.put(encrypted);

            return byteBuffer.array();
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not encrypt", e);
        } finally {
            Bytes.wrap(iv).mutable().secureWipe();
            Bytes.wrap(encrypted).mutable().secureWipe();
            Bytes.wrap(mac).mutable().secureWipe();
        }
    }

    @NotNull
    @Contract("_ -> new")
    private SecretKeySpec createEncryptionKey(byte[] rawEncryptionKey) {
        return new SecretKeySpec(HKDF.fromHmacSha256().expand(rawEncryptionKey, Bytes.from("encKey").array(), rawEncryptionKey.length), "AES");
    }

    private byte[] macCipherText(byte[] rawEncryptionKey, byte[] cipherText, byte[] iv) {
        SecretKey macKey = createMacKey(rawEncryptionKey);

        try {
            createHmacInstance();
            hmac.init(macKey);
            hmac.update(iv);
            hmac.update(cipherText);
        } catch (InvalidKeyException e) {
            // due to key generation in createMacKey(byte[]) this actually can not happen
            throw new IllegalStateException("error during HMAC calculation");
        }
        return hmac.doFinal();
    }

    @NotNull
    private SecretKey createMacKey(byte[] rawEncryptionKey) {
        byte[] derivedMacKey = HKDF.fromHmacSha256().expand(rawEncryptionKey, Bytes.from("macKey").array(), 32);
        return new SecretKeySpec(derivedMacKey, HMAC_ALGORITHM);
    }

    private synchronized Mac createHmacInstance() {
        if (hmac == null) {
            try {
                hmac = Mac.getInstance(HMAC_ALGORITHM);
            } catch (Exception e) {
                throw new IllegalStateException("could not get cipher instance", e);
            }
        }
        return hmac;
    }

    @Override
    public byte[] decrypt(byte[] rawEncryptionKey, byte[] encryptedData) throws AuthenticatedEncryptionException {
        checkAesKey(rawEncryptionKey);

        byte[] iv = null;
        byte[] mac = null;
        byte[] encrypted = null;
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

            int ivLength = (byteBuffer.get() & 0xFF);
            iv = new byte[ivLength];
            byteBuffer.get(iv);

            int macLength = (byteBuffer.get() & 0xFF);
            mac = new byte[macLength];
            byteBuffer.get(mac);

            encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);

            verifyMac(rawEncryptionKey, encrypted, iv, mac);

            final Cipher cipherDec = getCipher();
            cipherDec.init(Cipher.DECRYPT_MODE, createEncryptionKey(rawEncryptionKey), new IvParameterSpec(iv));
            return cipherDec.doFinal(encrypted);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not decrypt", e);
        } finally {
            Bytes.wrap(iv).mutable().secureWipe();
            Bytes.wrap(encrypted).mutable().secureWipe();
            Bytes.wrap(mac).mutable().secureWipe();
        }
    }

    private void verifyMac(byte[] rawEncryptionKey, byte[] cipherText, byte[] iv, byte[] mac) throws AuthenticatedEncryptionException {
        byte[] actualMac = macCipherText(rawEncryptionKey, cipherText, iv);

        if (!Bytes.wrap(mac).equalsContent(actualMac)) {
            throw new AuthenticatedEncryptionException("encryption integrity exception: mac does not match");
        }
    }

    @Contract(pure = true)
    @Override
    public int byteSizeLength(@KeyStrength int keyStrengthType) {
        return ((keyStrengthType == STRENGTH_HIGH) ? 16 : 32);
    }

    private void checkAesKey(@NotNull byte[] rawAesKey) throws IllegalArgumentException {
        int keyLen = rawAesKey.length;

        if ((keyLen != 16) && (keyLen != 32)) {
            throw new IllegalArgumentException("AES key length must be 16, 24, or 32 bytes");
        }
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

