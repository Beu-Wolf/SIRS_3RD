package sirs.server;

import java.nio.file.Path;

public class SharedFile {
    private Path _path;
    private byte[] _cipheredKey;
    private String _owner;

    public SharedFile(Path path, byte[] cipheredKey, String owner) {
        _path = path;
        _cipheredKey = cipheredKey;
        _owner = owner;
    }

    public Path getPath() {
        return _path;
    }

    public byte[] getCipheredKey() {
        return _cipheredKey;
    }

    public String getOwner() {
        return _owner;
    }
}
