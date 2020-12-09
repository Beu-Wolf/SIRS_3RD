package sirs.server;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class RRRDServer {

    public static void main(String[] args){
        String host = "localhost";
        int port = 10000;

        MainServer server = new MainServer(host, port);

        Runtime.getRuntime().addShutdownHook(new Thread() {

            List<FileInfo> _files = null;
            ConcurrentHashMap<String, ClientInfo> _clients;

            public void run() {
                System.out.println(" Forcing Exit.");
                _files = server.getFileInfo();
                _clients = server.getClients();

                try {
                    System.out.println(_clients);
                    FileOutputStream fileFilesOut =
                            new FileOutputStream("/tmp/files.ser");
                    FileOutputStream fileClientOut =
                            new FileOutputStream("/tmp/clients.ser");
                    ObjectOutputStream outFiles = new ObjectOutputStream(fileFilesOut);
                    ObjectOutputStream outClients = new ObjectOutputStream(fileClientOut);
                    outFiles.writeObject(_files);
                    outClients.writeObject(_clients);
                    outFiles.close();
                    outClients.close();
                    fileFilesOut.close();
                    fileClientOut.close();
                    System.out.println("Serialized data of Files is saved in /tmp/files.ser");
                    System.out.println("Serialized data of Clients is saved in /tmp/clients.ser");
                } catch (IOException i) {
                    i.printStackTrace();
                }
            }
        });

        server.start();

    }
}
