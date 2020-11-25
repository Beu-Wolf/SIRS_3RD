package Client.exceptions;

public class InvalidPathException extends Exception{
    private final String _message;

    public InvalidPathException(String message) { _message = message; }

    @Override
    public String getMessage() {
        return _message;
    }
}
