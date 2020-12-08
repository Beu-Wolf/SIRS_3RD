package sirs.server.exceptions;

public class NoPermissionException extends Exception{
    public NoPermissionException(String username, String path) {
        super("User " + username + " doesn't have access to " + path);
    }
}
