package sirs.server;

import java.io.File;
import java.util.ArrayList;

public class FileInfo {
    private File _file;
    private int _currentVersion = 1;
    private ClientInfo _owner;
    private ArrayList<ClientInfo> _editors = new ArrayList<>();
    private byte[] _signature;
    private ClientInfo _lastEditor;

    public FileInfo(File file, ClientInfo owner, byte[] signature, ClientInfo lastEditor) {
        _file = file;
        _owner = owner;
        _signature = signature;
        _lastEditor = lastEditor;
    }

    public ClientInfo getOwner() {
        return _owner;
    }

    public int getCurrentVersion() {
        return _currentVersion;
    }

    public ClientInfo getLastEditor() {
        return _lastEditor;
    }

    public void setLastEditor(ClientInfo lastEditor) {
        _lastEditor = lastEditor;
    }

    public File getFile() {
        return _file;
    }

    public byte[] getLatestSignature() {
        return _signature;
    }

    public void setLatestSignature(byte[] latestSignature) {
        _signature = latestSignature;
    }

    public void updateVersion() {
        _currentVersion++;
    }

    public ArrayList<ClientInfo> getEditors() { return _editors; }

    public void addEditor(ClientInfo client) {
        _editors.add(client);
    }

    public void removeEditor(ClientInfo client) { _editors.remove(client); }

    public boolean containsEditor(ClientInfo client) {
        return _editors.contains(client);
    }
}
