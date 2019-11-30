public class AuthenticatedEncryptionFactory {

    public static AuthenticatedEncryption getAuthenticatedEncryption(AuthenticatedEncryptionEnum encryptionEnum, String[] keys){
        AuthenticatedEncryption authenticatedEncryption;
        switch (encryptionEnum) {
            case Assym_RSA_ECB_PKCS1Padding:
                if (keys.length == 2){
                    authenticatedEncryption = new RsaEcbEncryption(keys[0], keys[1]);
                } else {
                    authenticatedEncryption = new RsaEcbEncryption();
                }
                break;
            case Sym_AES_CBC_PKCS5Padding:
                authenticatedEncryption = new AesCbcEncryption();
                break;
            case Sym_AES_GCM_NoPadding:
                authenticatedEncryption = new AesGcmEncryption();
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + encryptionEnum);
        }
        return authenticatedEncryption;
    }

}
