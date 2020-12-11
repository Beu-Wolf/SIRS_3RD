package sirs.server.exceptions;

public class SelfRevokeException extends Exception{
    public SelfRevokeException(String username, String path) {
        super("Can't revoke file " + path + " from owner: " + username);
    }
}
