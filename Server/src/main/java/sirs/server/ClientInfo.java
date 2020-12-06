package sirs.server;

import java.security.PublicKey;
import java.security.cert.Certificate;

public class ClientInfo {
    private Certificate _certificate;
    private String _username;
    private String _password;
    private boolean _online;

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
}
