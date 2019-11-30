public class Main {

    public static void main(String[] args) {
        byte[] plainText = HexBytesConverter.decodeHexString(StringHexConverter.stringToHex("https://www.google.com/"));
        byte[] correctEncryptedMsg;
        String rawEncryptionKey = "hardKey97531****";    // 16 Bytes key
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgFGVfrY4jQSoZQWWygZ83roKXWD4YeT2x2p41dGkPixe73rT2IW04glagN2vgoZoHuOPqa5and6kAmK2ujmCHu6D1auJhE2tXP+yLkpSiYMQucDKmCsWMnW9XlC5K7OSL77TXXcfvTvyZcjObEz6LIBRzs6+FqpFbUO9SJEfh6wIDAQAB";
        String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKAUZV+tjiNBKhlBZbKBnzeugpdYPhh5PbHanjV0aQ+LF7vetPYhbTiCVqA3a+Chmge44+prlqd3qQCYra6OYIe7oPVq4mETa1c/7IuSlKJgxC5wMqYKxYydb1eULkrs5IvvtNddx+9O/JlyM5sTPosgFHOzr4WqkVtQ71IkR+HrAgMBAAECgYAkQLo8kteP0GAyXAcmCAkA2Tql/8wASuTX9ITD4lsws/VqDKO64hMUKyBnJGX/91kkypCDNF5oCsdxZSJgV8owViYWZPnbvEcNqLtqgs7nj1UHuX9S5yYIPGN/mHL6OJJ7sosOd6rqdpg6JRRkAKUV+tmN/7Gh0+GFXM+ug6mgwQJBAO9/+CWpCAVoGxCA+YsTMb82fTOmGYMkZOAfQsvIV2v6DC8eJrSa+c0yCOTa3tirlCkhBfB08f8U2iEPS+Gu3bECQQCrG7O0gYmFL2RX1O+37ovyyHTbst4s4xbLW4jLzbSoimL235lCdIC+fllEEP96wPAiqo6dzmdH8KsGmVozsVRbAkB0ME8AZjp/9Pt8TDXD5LHzo8mlruUdnCBcIo5TMoRG2+3hRe1dHPonNCjgbdZCoyqjsWOiPfnQ2Brigvs7J4xhAkBGRiZUKC92x7QKbqXVgN9xYuq7oIanIM0nz/wq190uq0dh5Qtow7hshC/dSK3kmIEHe8z++tpoLWvQVgM538apAkBoSNfaTkDZhFavuiVl6L8cWCoDcJBItip8wKQhXwHp0O3HLg10OEd14M58ooNfpgt+8D8/8/2OOFaR0HzA+2Dm";
        String[] keys = {publicKey, privateKey};

        // only change this through some selector
        AuthenticatedEncryptionEnum encryptionEnum = AuthenticatedEncryptionEnum.Assym_RSA_ECB_PKCS1Padding;
        boolean doEncryption = true;

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
        byte[] encryptedMsg;
        byte[] decryptedMsg;

        if (doEncryption) {
            try {
                encryptedMsg = authenticatedEncryption.encrypt(rawEncryptionKey, plainText);
                System.out.println("Encrypted Msg is: ");
                System.out.println(StringBytesConverter.encodeString(encryptedMsg));
//                System.out.println(StringHexConverter.hexToString(HexBytesConverter.encodeHexString(encryptedMsg)));
            } catch (AuthenticatedEncryptionException e) {
                e.printStackTrace();
            }
        } else {
            try {
                decryptedMsg = authenticatedEncryption.decrypt(rawEncryptionKey, correctEncryptedMsg);
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
