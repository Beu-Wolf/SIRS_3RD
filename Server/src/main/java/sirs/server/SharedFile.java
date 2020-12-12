package sirs.server;

import java.io.Serializable;

public class SharedFile implements Serializable {
    private String _path; /* This is the same path entered by the user who shared the file */
    private byte[] _cipheredKey;
    private String _owner;

    private static final long serialVersionUID = 112342L;

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
