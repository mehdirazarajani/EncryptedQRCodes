import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Main {

    // returns [Public key, Private key]
    public static List<byte[]> generateKeyPair() throws NoSuchAlgorithmException {
        List<byte[]> keys = new ArrayList<>();
        KeyPairGenerator keyGen = null;
        PrivateKey privateKey;
        PublicKey publicKey;
        keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        keys.add(publicKey.getEncoded());
        keys.add(privateKey.getEncoded());
        return keys;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {

        List<byte[]> _keys = generateKeyPair();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(_keys.get(1));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey _privateKey = kf.generatePrivate(spec);
        X509EncodedKeySpec spec1 = new X509EncodedKeySpec(_keys.get(0));
        PublicKey _publicKey = kf.generatePublic(spec1);

        String s = "Some people send the most random text messages about the most random things. Often, for the recipie";
        String s1 = "4984b1d97f8213f65ca68f92c874161473478a5d7d7736154cea4773a0e391fdb441302e4bcc415448762a55260981659041aba0180d7548cc73ba7d3a0890a33f12947b939c93fe562e380edbbe2b807c0707394a0ea40784bac271e5cc981b6c540d44512942659bbc74e3dd53d9a316f5b9e3ccc67c1bef059f2b391dfc16";
//        byte[] plainText = HexBytesConverter.decodeHexString(StringHexConverter.stringToHex(s));
        byte[] plainText = HexBytesConverter.decodeHexString(s1);
        byte[] correctEncryptedMsg;
        String rawEncryptionKey = "hardKey97531****";    // 16 Bytes key
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqIeiqgHW9coUIAVSsh4o77SMfP2fko+9jnC2TZfELqfnZxd7EBq32GrrErMHl5dIUAX40qTX4nCa83335rl+zGklCIDsEBzFABTkhk8Qb7Xdd/2/dqLtrwCz81EpxktSxMZkxAFiLhCyNUJDw2Ci3tHLdDi4ryPqiTH9fvxzSGwIDAQAB";
        String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKAUZV+tjiNBKhlBZbKBnzeugpdYPhh5PbHanjV0aQ+LF7vetPYhbTiCVqA3a+Chmge44+prlqd3qQCYra6OYIe7oPVq4mETa1c/7IuSlKJgxC5wMqYKxYydb1eULkrs5IvvtNddx+9O/JlyM5sTPosgFHOzr4WqkVtQ71IkR+HrAgMBAAECgYAkQLo8kteP0GAyXAcmCAkA2Tql/8wASuTX9ITD4lsws/VqDKO64hMUKyBnJGX/91kkypCDNF5oCsdxZSJgV8owViYWZPnbvEcNqLtqgs7nj1UHuX9S5yYIPGN/mHL6OJJ7sosOd6rqdpg6JRRkAKUV+tmN/7Gh0+GFXM+ug6mgwQJBAO9/+CWpCAVoGxCA+YsTMb82fTOmGYMkZOAfQsvIV2v6DC8eJrSa+c0yCOTa3tirlCkhBfB08f8U2iEPS+Gu3bECQQCrG7O0gYmFL2RX1O+37ovyyHTbst4s4xbLW4jLzbSoimL235lCdIC+fllEEP96wPAiqo6dzmdH8KsGmVozsVRbAkB0ME8AZjp/9Pt8TDXD5LHzo8mlruUdnCBcIo5TMoRG2+3hRe1dHPonNCjgbdZCoyqjsWOiPfnQ2Brigvs7J4xhAkBGRiZUKC92x7QKbqXVgN9xYuq7oIanIM0nz/wq190uq0dh5Qtow7hshC/dSK3kmIEHe8z++tpoLWvQVgM538apAkBoSNfaTkDZhFavuiVl6L8cWCoDcJBItip8wKQhXwHp0O3HLg10OEd14M58ooNfpgt+8D8/8/2OOFaR0HzA+2Dm";

        String[] keys = {publicKey, privateKey};
//        String[] keys = generateKeyPair().toArray(new String[0]);


        // only change this through some selector
        AuthenticatedEncryptionEnum encryptionEnum = AuthenticatedEncryptionEnum.Assym_RSA_ECB_PKCS1Padding;
        boolean doEncryption = false;

        switch (encryptionEnum){
            case Sym_AES_GCM_NoPadding:
                correctEncryptedMsg = HexBytesConverter.decodeHexString("0c84f8ce1ffa15bc211e851ab30fb8e77f0217784baaa6e4e25757dbdf0068f57470e5348c22761ac6dfb31a5351050bc67f3ee5");
                break;
            case Sym_AES_CBC_PKCS5Padding:
                correctEncryptedMsg = HexBytesConverter.decodeHexString("10953a8341c78b326af56cc81e76c865b420a620042e52721ef5bb0966e7fb2340baf164a2d1589e2580eb446312e67944b1e33f6cf6384eb204f5892c3cb186476204eddc64d2bce4065ebe669649820eec");
                break;
            case Assym_RSA_ECB_PKCS1Padding:
                correctEncryptedMsg = HexBytesConverter.decodeHexString("740a4ba36791084b48306a788fbdafe231c01cf05d16dde7e1aa3d1f6d05641c00a101f0454cefb279e9c9ffc392a2f2888cd0995fc1290c8192d81f782088e9040913850a34bd896c059bc7d20ea4a84d719dfe70c352f45a67dd8a45a45f4179c957b1eef1060973a2b7a44756df1f02713a8daf1699d02dac239ed45ef508");
                break;
            default:
                correctEncryptedMsg = new byte[0];
        }


        AuthenticatedEncryption authenticatedEncryption;
        authenticatedEncryption = AuthenticatedEncryptionFactory.getAuthenticatedEncryption(encryptionEnum, keys);

        if (encryptionEnum.equals(AuthenticatedEncryptionEnum.Assym_RSA_ECB_PKCS1Padding)){
             RsaEcbEncryption _authenticatedEncryption = new RsaEcbEncryption(_publicKey,_privateKey);
             System.out.println(_authenticatedEncryption.encrypt(s,_publicKey));
//             System.out.println(_authenticatedEncryption.decrypt(StringBytesConverter.decodeString(s),_privateKey));
             byte[] temp = _authenticatedEncryption.encrypt(s,_publicKey);

             System.out.println(_authenticatedEncryption.decrypt(temp,_privateKey));
        }

        byte[] encryptedMsg;
        byte[] decryptedMsg;

        if (doEncryption) {
            try {
                encryptedMsg = authenticatedEncryption.encrypt(rawEncryptionKey, plainText);
                System.out.println("Encrypted Msg is: ");
                System.out.println(StringBytesConverter.encodeString(encryptedMsg));
                System.out.println(HexBytesConverter.encodeHexString(encryptedMsg));
            } catch (AuthenticatedEncryptionException e) {
                e.printStackTrace();
            }
        } else {
            try {
                decryptedMsg = authenticatedEncryption.decrypt(rawEncryptionKey, plainText);
                System.out.println("Decrypted Msg is: ");
                System.out.println(StringBytesConverter.encodeString(decryptedMsg));
                System.out.println(StringHexConverter.hexToString(HexBytesConverter.encodeHexString(decryptedMsg)));
                if (HexBytesConverter.encodeHexString(plainText).equals(HexBytesConverter.encodeHexString(decryptedMsg))) {
                    System.out.println("correct enc dec !!!");
                } else {
                    System.out.println("something went wrong !!!");
                }

            } catch (AuthenticatedEncryptionException e) {
                e.printStackTrace();
            }

        }

    }

}
