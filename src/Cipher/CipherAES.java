package Cipher;

import Errors.CipherError;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CipherAES {

    /*
        AES Wrapper class over the java.Cipher class, encrypts a stream and returns the reference
     */
    private byte[] input_stream = null;
    private byte[] output_stream = null;

    public static int BLOCK_SIZE = 16;
    public static int KEY_SIZE = 16;
    public static int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
    public static int DECRYPT_MODE = Cipher.DECRYPT_MODE;

    public CipherAES() {
        try {
            BLOCK_SIZE = Cipher.getInstance(TYPE).getBlockSize();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(CipherAES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static final String TYPE = "AES/CBC/PKCS5Padding";

    public byte[] cipher_operation(byte[] input, int mode, SecretKeySpec key, IvParameterSpec iv) throws CipherError {
        try {
            input_stream = input;
            Cipher cipher = Cipher.getInstance(TYPE);
            cipher.init(mode, key, iv);
            output_stream = cipher.doFinal(input_stream);
            byte[] ret_ref = output_stream;
            input_stream = null;
            output_stream = null;
            System.gc();
            return ret_ref;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException ex) {
            throw new CipherError("Error encrypting given input", ex); //todo
        }
    }

    public static SecretKeySpec generateKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[KEY_SIZE];
        random.nextBytes(bytes);
        SecretKeySpec spec = new SecretKeySpec(bytes, "AES");
        return spec;
    }

    public static IvParameterSpec generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[BLOCK_SIZE];
        random.nextBytes(bytes);
        return new IvParameterSpec(bytes);
    }
}
