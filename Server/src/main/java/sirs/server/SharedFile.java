package sirs.server;

public class SharedFile {
    private String _path; /* This is the same path entered by the user who shared the file */
    private byte[] _cipheredKey;
    private String _owner;

    public SharedFile(String path, byte[] cipheredKey, String owner) {
        _path = path;
        _cipheredKey = cipheredKey;
        _owner = owner;
    }

    public String getPath() {
        return _path;
    }

    public byte[] getCipheredKey() {
        return _cipheredKey;
    }

    public String getOwner() {
        return _owner;
    }
}
