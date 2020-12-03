package sirs.backup;

import java.io.File;
import java.util.Arrays;
import java.util.Objects;

public class BackupFileInfo {

    private File _file;
    private String _fileServerPath;
    private String _editor;
    private byte[] _signature;
    private int _version;

    public BackupFileInfo(File file, String fileServerPath,  String editor, byte[] signature, int version) {
        _file = file;
        _fileServerPath = fileServerPath;
        _editor = editor;
        _signature = signature;
        _version = version;
    }

    public File getFile() {
        return _file;
    }

    public byte[] getSignature() {
        return _signature;
    }

    public String getEditor() {
        return _editor;
    }

    public String getFileServerPath() {
        return _fileServerPath;
    }

    public int getVersion() {
        return _version;
    }

}
