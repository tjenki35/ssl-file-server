package Errors;

/**
 * Exception class for the Msg Package
 */
public class MessageError extends Exception {

    public MessageError(String reason) {
        super(reason);
    }

    public MessageError(String reason, Exception ex) {
        super(reason, ex);
    }

}
