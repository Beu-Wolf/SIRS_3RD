package sirs.backup;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ConcurrentHashMap;

public class Main {
    public static void main(String[] args) {
        String host = "localhost";
        int port = 20000;

        BackupServer server = new BackupServer(host, port);

        Runtime.getRuntime().addShutdownHook(new Thread() {

            ConcurrentHashMap<String, BackupFileInfo> _files = null;

            public void run() {
                System.out.println(" Forcing Exit.");

                _files = server.getFileInfo();
                try {
                    Path backupPath = Paths.get("tmp/backup.ser");
                    Files.deleteIfExists(backupPath);

                    FileOutputStream fileFilesOut =
                            new FileOutputStream(backupPath.toFile());

                    ObjectOutputStream outFiles = new ObjectOutputStream(fileFilesOut);
                    outFiles.writeObject(_files);
                    outFiles.close();
                    fileFilesOut.close();
                    System.out.println("Serialized data of Backup is saved in /tmp/backup.ser");

                } catch (IOException i) {
                    i.printStackTrace();
                }
            }
         });

        server.start();
    }
}