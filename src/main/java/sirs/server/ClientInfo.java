package sirs.server;

import java.security.PublicKey;

public class ClientInfo {
    private String _url;
    private PublicKey _publicKey;
    private String _username;

    public ClientInfo(String url, PublicKey publicKey, String username) {
        _url = url;
        _publicKey = publicKey;
        _username = username;
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
}
