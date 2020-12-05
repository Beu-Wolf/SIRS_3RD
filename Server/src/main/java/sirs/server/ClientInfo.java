package sirs.server;

import java.security.PublicKey;

public class ClientInfo {
    private String _url;
    private PublicKey _publicKey;
    private String _username;
    private String _email;
    private String _password;
    private boolean _online;

    public ClientInfo(String url, PublicKey publicKey, String username, String email, String password) {
        _url = url;
        _publicKey = publicKey;
        _username = username;
        _email = email;
        _password = password;
        _online = false;
    }

    public PublicKey getPublicKey() {
        return _publicKey;
    }

    public String getUrl() {
        return _url;
    }

    public String getUsername() {
        return _username;
    }

    public String getEmail() {
        return _email;
    }

    public String getPassword() { return _password; }

    public boolean isOnline () { return _online; }

    public void setUserOnline(boolean status) { _online = status;}
}
