package adp.io.security.crypters;

public interface IByteCrypter {
    byte[] encryptBytes(byte[] toEncrypt) throws Exception;
    byte[] decryptBytes(byte[] toDecrypt) throws Exception;
}
