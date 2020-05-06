package adp.io.security.files;

import adp.io.SimpleSerializer;
import adp.io.security.crypters.IStringCrypter;
import adp.io.security.crypters.aes_crypter;

import java.io.Serializable;

public class SecureObjectFileIO {

    public static void SecureObjectFileExport(IStringCrypter myPrivateCrypter, Serializable toExport, String path, String fileName) {

        try {

            aes_crypter singleServingEncrypter = new aes_crypter();

            String
                persistentKeyEncrypted_oneTimeKey = myPrivateCrypter.encryptString(singleServingEncrypter.getPublicKey()),
                encryptedFileName = singleServingEncrypter.encryptString(fileName);

            byte[]  bytes_toExport = singleServingEncrypter.encryptBytes(SimpleSerializer.serializeObject(toExport));

            SecureFile secureFile = new SecureFile(persistentKeyEncrypted_oneTimeKey, encryptedFileName, bytes_toExport);

            SimpleSerializer.exportObjectToFile(secureFile, path, fileName);

        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

    }

    public static Object SecureObjectFileImport(IStringCrypter myPrivateCrypter, String path, String fileName) {

        try {

            SecureFile secureFile = (SecureFile) SimpleSerializer.importObjectFromFile(path+fileName);

            aes_crypter singleServingDecrypter = new aes_crypter(myPrivateCrypter.decryptString(secureFile.encryptedDecryptionKey));

            String decryptionTest = singleServingDecrypter.decryptString(secureFile.encryptedFileName);

            if(!decryptionTest.equals(fileName))
                throw new Exception("SecureFile Decryption Check Failed!");

            System.out.println("SecureFile Decryption Successful: " + fileName);

            Object toReturn = SimpleSerializer.deserializeObject(singleServingDecrypter.decryptBytes(secureFile.encryptedFileBytes));

            return toReturn;

        } catch (Exception ex) {

            String msg = ex.getMessage();
            if(msg.contains("cannot find the file"))
                System.out.println("SecureFile Import Error. File Not Found: " + fileName);
            else
                ex.printStackTrace(System.out);

        }

        return null;

    }

}
