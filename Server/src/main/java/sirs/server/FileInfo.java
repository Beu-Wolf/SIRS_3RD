package sirs.server;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.util.ArrayList;

public class FileInfo {
    private File _file;
    private int _currentVersion = 1;
    private ClientInfo _owner;
    private ArrayList<ClientInfo> _editors = new ArrayList<>();
    private byte[] _latestChecksum;

    public FileInfo(File file, ClientInfo owner, byte[] latestChecksum) {
        _file = file;
        _owner = owner;
        _latestChecksum = latestChecksum;
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

    public byte[] getLatestChecksum() {
        return _latestChecksum;
    }

    public void setLatestChecksum(byte[] LatestChecksum) {
        _latestChecksum = LatestChecksum;
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
