import org.jetbrains.annotations.Nullable;

public interface AuthenticatedEncryption {
    @interface KeyStrength {
    }

    /**
     * High Security which is equivalent to a AES key size of 128 bit
     */
    int STRENGTH_HIGH = 0;

    /**
     * Very high security which is equivalent to a AES key size of 256 bit
     * Note: This is usually not required.
     */
    int STRENGTH_VERY_HIGH = 1;

    /**
     * Encrypts and adds a authentication tag the given content
     *
     * @param rawEncryptionKey to use as encryption key material
     * @param rawData          to encrypt
     * @return encrypted content
     * @throws AuthenticatedEncryptionException if any crypto fails
     */
    byte[] encrypt(String rawEncryptionKey, byte[] rawData) throws AuthenticatedEncryptionException;

    /**
     * Decrypt and verifies the authenticity of given encrypted data
     *
     * @param rawEncryptionKey to use as decryption key material
     * @param encryptedData    to decrypt
     * @return decrypted, original data
     * @throws AuthenticatedEncryptionException if any crypto fails
     */
    byte[] decrypt(String rawEncryptionKey, byte[] encryptedData) throws AuthenticatedEncryptionException;

    /**
     * Get the required key size length in bytes for given security strength type
     *
     * @param keyStrengthType STRENGTH_HIGH or STRENGTH_VERY_HIGH
     * @return required size in byte
     */
    int byteSizeLength(@KeyStrength int keyStrengthType);

}
