package adp.io.security.crypters;

public interface IStringCrypter {
    String encryptString(String toEncrypt) throws Exception;
    String decryptString(String toDecrypt) throws Exception;

    String getPublicKey();

    static String generateOverwriteString(int length) {

        String toBlankWith = "*";

        while(toBlankWith.length() < length)
            toBlankWith+=toBlankWith;

        return toBlankWith;

    }

}
