package Client;

import javax.crypto.SecretKey;
import java.io.File;
import java.util.Arrays;
import java.util.Objects;

public class FileInfo {
    private String _owner;
    private File _file;
    private SecretKey _fileSymKey;

    public FileInfo(String owner, File file, SecretKey symKey) {
        _owner = owner;
        _file = file;
        _fileSymKey = symKey;
    }

    public String getOwner() {
        return _owner;
    }

    public File getFile() {
        return _file;
    }

    public SecretKey getFileSymKey() {
        return _fileSymKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FileInfo fileInfo = (FileInfo) o;
        return  _owner.equals(fileInfo.getOwner()) && _file.compareTo(fileInfo.getFile()) == 0 && Arrays.equals(_fileSymKey.getEncoded(), fileInfo.getFileSymKey().getEncoded());
    }

    @Override
    public int hashCode() {
        return Objects.hash(_file, _fileSymKey);
    }
}
