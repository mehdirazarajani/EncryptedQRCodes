import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaEcbEncryption implements AuthenticatedEncryption {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private boolean useKeyStr;

    RsaEcbEncryption() {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
            this.useKeyStr = true;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Contract(pure = true)
    RsaEcbEncryption(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.useKeyStr = false;
    }

    RsaEcbEncryption(String publicKey, String privateKey) {
        try {
            this.privateKey = getPrivateKey(privateKey);
            this.publicKey = getPublicKey(publicKey);
            this.useKeyStr = false;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public byte[] encrypt(String rawEncryptionKey, byte[] rawData) throws AuthenticatedEncryptionException {
        try {
            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            if (useKeyStr) {
                cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(rawEncryptionKey));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            }
            return cipher.doFinal(rawData);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not encrypt", e);
        }
    }

    public byte[] encrypt(String data, PublicKey publicKey){
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data.getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(byte[] data, PrivateKey privateKey){
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(data));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return "";
    }


    public byte[] decrypt(String rawEncryptionKey, byte[] encryptedData) throws AuthenticatedEncryptionException {
        try {
            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            if (useKeyStr) {
                cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(rawEncryptionKey));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
            }
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not decrypt", e);
        }
    }

    @Override
    public int byteSizeLength(@KeyStrength int keyStrengthType) {
        return keyStrengthType == STRENGTH_HIGH ? 16 : 32;
    }

    private PublicKey getPublicKey(@NotNull String base64PublicKey) throws AuthenticatedEncryptionException {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not get public key: ", e);
        }
    }


    private PrivateKey getPrivateKey(@NotNull String base64PrivateKey) throws AuthenticatedEncryptionException {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not get private key:", e);
        }
        return privateKey;
    }
}
