package dev.sanda.authentifi.web.exceptions;

public class InvalidInviteAttemptException extends Exception {
    public InvalidInviteAttemptException(String message) {
        super("InvalidInviteAttemptException: " + message);
    }
}
