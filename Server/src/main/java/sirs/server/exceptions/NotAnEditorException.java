package sirs.server.exceptions;

public class NotAnEditorException extends Exception{
    public NotAnEditorException(String username, String path) {
        super("User " + username + " isn't an editor of " + path);
    }
}
