package sirs.server;

import java.io.File;
import java.util.ArrayList;

public class FileInfo {
    private File _file;
    private int _currentVersion = 1;
    private ClientInfo _owner;
    private ArrayList<ClientInfo> _editors = new ArrayList<>();
    private byte[] _signature;

    public FileInfo(File file, ClientInfo owner, byte[] signature) {
        _file = file;
        _owner = owner;
        _signature = signature;
    }

    public ClientInfo getOwner() {
        return _owner;
    }

    public int getCurrentVersion() {
        return _currentVersion;
    }

    public File getFile() {
        return _file;
    }

    public byte[] getLatestSignature() {
        return _signature;
    }

    public void setLatestChecksum(byte[] latestSignature) {
        _signature = latestSignature;
    }

    public void updateVersion() {
        _currentVersion++;
    }

    public void addEditor(ClientInfo client) {
        _editors.add(client);
    }

    public boolean containsEditor(ClientInfo client) {
        return _editors.contains(client);
    }
}
