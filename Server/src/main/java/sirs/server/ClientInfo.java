package sirs.server;

import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.stream.Collectors;

public class ClientInfo implements java.io.Serializable {
    private Certificate _certificate;
    private String _username;
    private String _password;
    private boolean _online;
    private HashMap<String, SharedFile> _sharedFiles = new HashMap<>();

    private static final long serialVersionUID = 42L;

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

    public void shareFile(String path, byte[] cipheredKey, String owner) {
        _sharedFiles.put(owner + "/" + path, new SharedFile(path, cipheredKey, owner));
    }

    public boolean hasSharedFiles() {
        return !_sharedFiles.isEmpty();
    }

    public Collection<SharedFile> getSharedFiles() {
        return _sharedFiles.values();
    }

    public void revokeFile(String path, String owner) {
        _sharedFiles.remove(owner + "/" + path);
    }
}
