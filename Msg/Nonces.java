package Msg;

import Errors.NonceError;
import java.security.SecureRandom;
import java.util.Arrays;

public class Nonces {

    //static indentifier for the size of nonce (in 8-bit bytes)
    public static int NONCE_SIZE = 16; // 128 bits for nonce size (for AES keys)

    //Generates a nonce using the secure random interface
    public static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[NONCE_SIZE];
        random.nextBytes(bytes);
        return bytes;
    }

    //verifies a tranformation of a nonce
    public static void verifyNonce(byte[] nonce, byte[] nonce_) throws NonceError {
        boolean flag = Arrays.equals(changeNonce(nonce), nonce_);
        if (!flag) {
            throw new NonceError("Nonces Do Not Match!");
        }
    }

    //should this just be a hash function of the nonce maybe? ** (right now it is just a singular byte swap)
    //transforms a nonce in such a way that it is verifiable
    public static byte[] changeNonce(byte[] bytes) {
        for (int i = 0; i < NONCE_SIZE / 2; i++) {
            byte temp = bytes[i];
            bytes[i] = bytes[NONCE_SIZE - i - 1];
            bytes[NONCE_SIZE - i - 1] = temp;
        }
        return bytes;
    }

}
