public class Main {

    public static void main(String[] args) {
//        byte[] plainText = HexBytesConverter.decodeHexString("e04fd020ea3a6910a2d808002b30309d");
        byte[] plainText = HexBytesConverter.decodeHexString(StringHexConverter.stringToHex("https://www.google.com/"));
        byte[] correctEncryptedMsg;
//        byte[] rawEncryptionKey = HexBytesConverter.decodeHexString("12345678123456781234567812345678");
        byte[] rawEncryptionKey = HexBytesConverter.decodeHexString(StringHexConverter.stringToHex("hardKey97531****"));    // 16 Bytes key

        AuthenticatedEncryption authenticatedEncryption;
        byte[] encryptedMsg;
        byte[] decryptedMsg;

        boolean useAecCbc = false;
        boolean doEncryption = false;

        if (useAecCbc){
            authenticatedEncryption = new AesCbcEncryption();
            correctEncryptedMsg = HexBytesConverter.decodeHexString("10953a8341c78b326af56cc81e76c865b420a620042e52721ef5bb0966e7fb2340baf164a2d1589e2580eb446312e67944b1e33f6cf6384eb204f5892c3cb186476204eddc64d2bce4065ebe669649820eec");
        } else {
            authenticatedEncryption = new AesGcmEncryption();
            correctEncryptedMsg = HexBytesConverter.decodeHexString("0c84f8ce1ffa15bc211e851ab30fb8e77f0217784baaa6e4e25757dbdf0068f57470e5348c22761ac6dfb31a5351050bc67f3ee5");
        }

        if (doEncryption){
            try {
                encryptedMsg = authenticatedEncryption.encrypt(rawEncryptionKey, plainText);
                if (HexBytesConverter.encodeHexString(encryptedMsg).equals(HexBytesConverter.encodeHexString(correctEncryptedMsg))) {
                    System.out.println("correct enc dec !!!");
                } else {
                    System.out.println("something went wrong !!!");
                }
            } catch (AuthenticatedEncryptionException e) {
                e.printStackTrace();
            }
        }
        else {
            try {
                decryptedMsg = authenticatedEncryption.decrypt(rawEncryptionKey, correctEncryptedMsg);
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
