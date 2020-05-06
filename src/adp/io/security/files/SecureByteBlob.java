package adp.io.security.files;

import adp.io.security.crypters.aes_crypter;
import adp.io.security.crypters.rsa_crypter;

import java.io.Serializable;

public class SecureByteBlob implements Serializable {

    final private byte[] bytes;
    final private String encryptedKey;

    //-

    public SecureByteBlob(byte[] bytes, String destination_publicKey) throws Exception {

        rsa_crypter rsaCrypter = new rsa_crypter();
        rsaCrypter.setPartnersPublicKey(destination_publicKey);

        aes_crypter aesCrypter = new aes_crypter();

        this.encryptedKey = rsaCrypter.encryptString(aesCrypter.getPublicKey());
        this.bytes = aesCrypter.encryptBytes(bytes);

    }

    public byte[] decrypt(rsa_crypter privateCrypter) throws Exception {
        return new aes_crypter(privateCrypter.decryptString(encryptedKey)).decryptBytes(bytes);
    }

}
