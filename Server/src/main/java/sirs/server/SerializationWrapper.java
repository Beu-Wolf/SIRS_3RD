package sirs.server;

import java.io.Serializable;
import java.util.concurrent.ConcurrentHashMap;

public class SerializationWrapper implements Serializable {
    private static final long serialVersionUID = 124567L;

    private ConcurrentHashMap<String, ClientInfo> _clients;
    private ConcurrentHashMap<String, FileInfo> _files;

    public SerializationWrapper(ConcurrentHashMap<String, ClientInfo> clients, ConcurrentHashMap<String, FileInfo> files) {
        _clients = clients;
        _files = files;
    }

    public ConcurrentHashMap<String, ClientInfo> getClients() {
        return _clients;
    }

    public ConcurrentHashMap<String, FileInfo> getFiles() {
        return _files;
    }
}
