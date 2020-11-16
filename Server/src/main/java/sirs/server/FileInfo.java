package sirs.server;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;

public class FileInfo {
    private File _file;
    private int _currentVersion = 1;
    private ClientInfo _owner;
    private SecretKeySpec _fileKey;

    public FileInfo(File file, ClientInfo owner, SecretKeySpec fileKey) {
        _file = file;
        _owner = owner;
        _fileKey = fileKey;
    }

    public ClientInfo getOwner() {
        return _owner;
    }

    public int getCurrentVersion() {
        return _currentVersion;
    }

    public SecretKeySpec getFileKey() {
        return _fileKey;
    }

    public File getFile() {
        return _file;
    }

    public void updateVersion() {
        _currentVersion++;
    }
}
