package Errors;

/**
 * Exception class for Nonces and Nonce verifications
 */
public class NonceError extends Exception {

    public NonceError(String reason, Exception ex) {
        super(reason, ex);
    }

    public NonceError(String reason) {
        super(reason);
    }

}
