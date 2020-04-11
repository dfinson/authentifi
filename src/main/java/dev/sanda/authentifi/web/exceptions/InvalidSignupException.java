package dev.sanda.authentifi.web.exceptions;



public class InvalidSignupException extends Exception {
    public InvalidSignupException(String message) {
        super("InvalidSignupException: " + message);
    }
}
