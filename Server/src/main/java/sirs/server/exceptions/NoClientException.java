package sirs.server.exceptions;

public class NoClientException extends Exception {

    public NoClientException(String username) {
        super("No Client exists with username " + username);
    }
}
