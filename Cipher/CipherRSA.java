package Cipher;

import java.math.BigInteger;

//Class for RSA related functions (currently implemented as a static type class for simplicity)
public class CipherRSA {

    /*
      Stripped Down version of the CipherRSA class, just has a wrapper for a modular exponentation
      Note these two are the same operation, just aesthetically the difference is helpful
     */

    //public interface for encryption
    public static BigInteger encrypt(BigInteger input, BigInteger key, BigInteger modulus) {
        return modular_expo(input, key, modulus);
    }

    //private interface for decryption
    public static BigInteger decrypt(BigInteger cipher, BigInteger key, BigInteger modulus) {
        return modular_expo(cipher, key, modulus);
    }

    //modular exponentation algorithm for this class
    private static BigInteger modular_expo(BigInteger x, BigInteger y, BigInteger N) {
        if (y.compareTo(BigInteger.ZERO) == 0) {
            return BigInteger.ONE;
        } else {
            BigInteger z = modular_expo(x, y.divide(BigInteger.valueOf(2)), N);
            BigInteger precompute = z.mod(N).pow(2).mod(N);
            return (y.mod(BigInteger.valueOf(2)).compareTo(BigInteger.ZERO) == 0) ? precompute : precompute.multiply(x.mod(N)).mod(N);
        }
    }
}
