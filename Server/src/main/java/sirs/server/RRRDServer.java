package sirs.server;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ConcurrentHashMap;

public class RRRDServer {

    public static void main(String[] args){
        String host = "localhost";
        String backupHost = null;
        int port = 10000;

        if (args.length > 1) {
            System.err.println("Usage: client [backup_host]");
            System.exit(1);
        } else if (args.length == 1) {
            backupHost = args[0];
        } else {
            backupHost = "localhost";
        }

        MainServer server = new MainServer(host, port, backupHost);

        Runtime.getRuntime().addShutdownHook(new Thread() {


            public void run() {
                System.out.println(" Forcing Exit.");

                SerializationWrapper serializationWrapper = new SerializationWrapper(server.getClients(), server.getFileInfo());

                try {

                    Path serverSerPath = Paths.get("tmp/server.ser");
                    Files.deleteIfExists(serverSerPath);

                    FileOutputStream fileFilesOut =
                            new FileOutputStream(serverSerPath.toFile());

                    ObjectOutputStream outFiles = new ObjectOutputStream(fileFilesOut);
                    outFiles.writeObject(serializationWrapper);
                    outFiles.close();
                    fileFilesOut.close();
                    System.out.println("Serialized data of Server is saved in /tmp/server.ser");
                } catch (IOException i) {
                    i.printStackTrace();
                }
            }
        });

        server.start();

    }
}
