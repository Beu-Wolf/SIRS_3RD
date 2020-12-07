package sirs.server.exceptions;

public class InvalidEditorException extends Exception{
    public InvalidEditorException(String username, String path) {
        super("User " + username + " cannot edit " + path);
    }
}
