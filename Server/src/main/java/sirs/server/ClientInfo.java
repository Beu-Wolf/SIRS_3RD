package sirs.server;

import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.LinkedList;

public class ClientInfo {
    private Certificate _certificate;
    private String _username;
    private String _password;
    private boolean _online;
    private LinkedList<SharedFile> _sharedFiles = new LinkedList<>();

    public ClientInfo(Certificate certificate, String username, String password) {
        _certificate = certificate;
        _username = username;
        _password = password;
        _online = false;
    }

    public PublicKey getPublicKey() {
        return _certificate.getPublicKey();
    }

    public String getUsername() {
        return _username;
    }

    public String getPassword() { return _password; }

    public boolean isOnline () { return _online; }

    public void setUserOnline(boolean status) { _online = status;}

    public void shareFile(Path path, byte[] cipheredKey, String owner) {
        _sharedFiles.add(new SharedFile(path, cipheredKey, owner));
    }

    public boolean hasSharedFiles() {
        return !_sharedFiles.isEmpty();
    }

    public LinkedList<SharedFile> getSharedFiles() {
        return _sharedFiles;
    }
}
