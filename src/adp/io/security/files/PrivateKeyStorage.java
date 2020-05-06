package adp.io.security.files;

import java.io.Serializable;

public class PrivateKeyStorage implements Serializable {

    public final byte[]
            passwordSalt,
            encryptionKeyName,//known string for decryption test
            encryptedKeyInitialVariation,//salt
            encryptedPrivateKey,
            encryptedPublicKey;

    public PrivateKeyStorage(byte[] passwordSalt, byte[] encryptionKeyName, byte[] encryptedKeyInitialVariation, byte[] encryptedPrivateKey, byte[] encryptedPublicKey) {
        this.passwordSalt = passwordSalt;
        this.encryptionKeyName = encryptionKeyName;
        this.encryptedKeyInitialVariation = encryptedKeyInitialVariation;
        this.encryptedPrivateKey = encryptedPrivateKey;
        this.encryptedPublicKey = encryptedPublicKey;
    }

}