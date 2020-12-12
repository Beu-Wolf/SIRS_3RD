package sirs.backup;

import java.io.File;
import java.util.Arrays;
import java.util.Objects;

public class BackupFileInfo implements java.io.Serializable {

    private File _file;
    private String _editor;
    private byte[] _signature;

    private static final long serialVersionUID = -845516367539358903L;

    public BackupFileInfo(File file,  String editor, byte[] signature) {
        _file = file;
        _editor = editor;
        _signature = signature;
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

}
