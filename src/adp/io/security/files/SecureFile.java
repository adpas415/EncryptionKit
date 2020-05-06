package adp.io.security.files;

import java.io.Serializable;

public class SecureFile implements Serializable {
    public final String encryptedDecryptionKey;
    public final String encryptedFileName;
    public final byte[] encryptedFileBytes;

    public SecureFile(String encryptedDecryptionKey, String encryptedFileName, byte[] encryptedFileBytes) {
        this.encryptedDecryptionKey = encryptedDecryptionKey;
        this.encryptedFileName = encryptedFileName;
        this.encryptedFileBytes = encryptedFileBytes;
    }
}