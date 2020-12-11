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
        int port = 10000;

        MainServer server = new MainServer(host, port);

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
