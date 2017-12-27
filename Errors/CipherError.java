package Errors;

/**
 * Exception class for the Cipher Package
 */
public class CipherError extends Exception {

    public CipherError(String msg, Exception ex) {
        super(msg, ex);
    }

    public CipherError(String msg) {
        super(msg);
    }

}
