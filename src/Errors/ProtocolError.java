package Errors;

/**
 * Exception class for the protocol related errors
 */
public class ProtocolError extends Exception {

    public ProtocolError(String message) {
        super(message);
    }

    public ProtocolError(String message, Throwable cause) {
        super(message, cause);
    }

}
