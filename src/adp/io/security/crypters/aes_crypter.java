package adp.io.security.crypters;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class aes_crypter implements IStringCrypter, IByteCrypter {

    private static String cipher = "AES/CBC/PKCS5Padding";

    Cipher
        encrypter,
        decrypter;

    Key sharedKey;

    byte[] randomBytes = new byte[16];

    public aes_crypter(String sharedKey_str) {

        try {

            String[] split = sharedKey_str.split("§§§");
            byte[] keyBytes = Base64.getDecoder().decode(split[0]);
            randomBytes = Base64.getDecoder().decode(split[1]);
            sharedKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");

            setup();

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

    }

    public aes_crypter() {

        try { // generate key

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(192);

            SecureRandom.getInstance("SHA1PRNG").nextBytes(randomBytes);
            sharedKey = keyGen.generateKey();

            setup();

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

    }

    void setup() throws Exception {

        decrypter = Cipher.getInstance(cipher);
        encrypter = Cipher.getInstance(cipher);

        IvParameterSpec thisMsg_ivSpec = new IvParameterSpec(randomBytes);

        decrypter.init(Cipher.DECRYPT_MODE, sharedKey, thisMsg_ivSpec);
        encrypter.init(Cipher.ENCRYPT_MODE, sharedKey, thisMsg_ivSpec);

    }

    @Override
    public String encryptString(String toEncrypt) throws Exception {
        return Base64.getEncoder().encodeToString(encrypter.doFinal(toEncrypt.getBytes()));
    }

    @Override
    public String decryptString(String toDecrypt) throws Exception {
        return new String(decrypter.doFinal(Base64.getDecoder().decode(toDecrypt)));
    }

    @Override
    public String getPublicKey() {//this is actually a shared private key but whatever
        return Base64.getEncoder().encodeToString(sharedKey.getEncoded()) + "§§§" + Base64.getEncoder().encodeToString(randomBytes);
    }

    @Override
    public byte[] encryptBytes(byte[] toEncrypt) throws Exception {
        return encrypter.doFinal(toEncrypt);
    }

    @Override
    public byte[] decryptBytes(byte[] toDecrypt) throws Exception {
        return decrypter.doFinal(toDecrypt);
    }

}
