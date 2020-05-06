package adp.io.security.crypters;

import adp.io.SimpleSerializer;
import adp.io.security.files.PrivateKeyStorage;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class rsa_crypter implements IStringCrypter {

    protected final static String
        storageDirectory = "mp/",
        privateKeyExtension = ".pk";

    Cipher
        encryptForPartner,
        decryptFromPartner;

    //-

    protected  PrivateKey  key_private;
    public     PublicKey   key_public;

    public boolean keyExists(String keyName) {

        File
            homedir = new File(System.getProperty("user.home")),
            fileToRead = new File(homedir, storageDirectory+keyName + privateKeyExtension);

        return fileToRead.exists();

    }

    public void exportKeyPair(String keyName, String password) {

        try {

            //generate some chaos salt
            final byte[] saltForPasswordDerivedKey = new byte[64];
            SecureRandom.getInstanceStrong().nextBytes(saltForPasswordDerivedKey);

            //initiate the password based encrypter
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(password.toCharArray(), saltForPasswordDerivedKey, 65536, 256)).getEncoded(), "AES"));

            byte[] //encrypt the key pair
                passwordDerivedCrypter_InitialVariation = c.getIV(),
                encryptedKeyName     =  c.doFinal(keyName.getBytes()),
                encryptedPublicKey   =  c.doFinal(key_public.getEncoded()),
                encryptedPrivateKey  =  c.doFinal(key_private.getEncoded());

            //export excrypted privateKey and salts
            SimpleSerializer.exportObjectToFile(new PrivateKeyStorage(saltForPasswordDerivedKey, encryptedKeyName, passwordDerivedCrypter_InitialVariation, encryptedPrivateKey, encryptedPublicKey), System.getProperty("user.home")+"/"+storageDirectory, keyName+privateKeyExtension);

            //overwrite the password in memory before it is handed to GC. Just incase.
            password = IStringCrypter.generateOverwriteString(password.length()*2);

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

    }

    public boolean importKeyPair(String keyName, String password) {

        try {

            //deserialize key storage file
            PrivateKeyStorage privateKey = (PrivateKeyStorage) SimpleSerializer.importObjectFromFile(System.getProperty("user.home")+"/"+storageDirectory+keyName + privateKeyExtension);

            //initiate password-based decrypter
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(password.toCharArray(), privateKey.passwordSalt, 65536, 256)).getEncoded(), "AES"), new IvParameterSpec(privateKey.encryptedKeyInitialVariation));

            //test decryption with a known string (keyName)
            if(!new String(c.doFinal(privateKey.encryptionKeyName)).equals(keyName))
                throw new Exception("Decryption Check Failed! Incorrect Password!");

            //implicit success
            System.out.println("Successfully Decrypted Persistent Private Key!");

            //-

            // decrypt keypair
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            key_public  = keyFactory.generatePublic(new X509EncodedKeySpec(c.doFinal(privateKey.encryptedPublicKey)));
            key_private = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(c.doFinal(privateKey.encryptedPrivateKey)));

            //-

            decryptFromPartner = Cipher.getInstance("RSA");
            decryptFromPartner.init(Cipher.DECRYPT_MODE, key_private);

            encryptForPartner =  Cipher.getInstance("RSA");
            encryptForPartner.init(Cipher.ENCRYPT_MODE, key_public);

            //overwrite the password in memory before it is handed to GC. Just incase.
            password = IStringCrypter.generateOverwriteString(password.length()*2);

            return true;

        } catch (Exception ex) {
            System.out.println("Failed to Import Key!");
        }

        //overwrite the password in memory before it is handed to GC. Just incase.
        password = IStringCrypter.generateOverwriteString(password.length()*2);

        return false;

    }

    public rsa_crypter() {

        try {

            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
            kpGen.initialize(1024);
            KeyPair keyPair = kpGen.generateKeyPair();

            key_private  =  keyPair.getPrivate();
            key_public   =  keyPair.getPublic();

            //-

            decryptFromPartner = Cipher.getInstance("RSA");
            decryptFromPartner.init(Cipher.DECRYPT_MODE, key_private);

            encryptForPartner =  Cipher.getInstance("RSA");
            encryptForPartner.init(Cipher.ENCRYPT_MODE, key_public);

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

    }

    @Override
    public String decryptString(String toDecrypt) throws Exception {
        return new String(decryptFromPartner.doFinal(Base64.getDecoder().decode(toDecrypt)));
    }

    @Override
    public String encryptString(String toEncrypt) throws Exception {
        return Base64.getEncoder().encodeToString(encryptForPartner.doFinal(toEncrypt.getBytes()));
    }

    @Override
    public String getPublicKey() {
        return key_public.toString();
    }

    public void setPartnersPublicKey(String partnersPublicKey) {

        //todo: clean up the string format when swapping keys to just be modulus & exponent

        int indexOfModulus = partnersPublicKey.indexOf("modulus: "),
            indexOfExponent = partnersPublicKey.indexOf("public exponent: ");

        String
            modulus_String = partnersPublicKey.substring(indexOfModulus + "modulus: ".length(), partnersPublicKey.indexOf("\n", indexOfModulus)),
            public_exponent = partnersPublicKey.substring(indexOfExponent + "public exponent: ".length());

        try {

            encryptForPartner = Cipher.getInstance("RSA");
            encryptForPartner.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(new BigInteger(modulus_String), new BigInteger(public_exponent))));

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

    }

}
