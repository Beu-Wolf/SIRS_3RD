package sirs.server.exceptions;

public class MissingFileException extends Exception{
    public MissingFileException(String path) {
        super("No file with path " + path);
    }
}
