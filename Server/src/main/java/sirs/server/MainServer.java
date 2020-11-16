package sirs.server;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.TreeMap;

public class MainServer {
    private TreeMap<String, ClientInfo> _clients = new TreeMap<>();
    private ArrayList<FileInfo> _files = new ArrayList<>();


    private String _host;
    private int _port;

    public MainServer(String host, int port) {
        _host = host;
        _port = port;
    }

    public void close() {
        System.out.println("Closing");
    }

    public void run() {
        System.out.println("Running at " + _host + ":" + _port);
        // Initiate Server
        Scanner scanner = new Scanner(System.in);

        while (scanner.nextLine().length() != 0){
            // do classic stuff
        }
        close();
    }

    public void receiveUserKey(String url, PublicKey publicKey, String username) { // Can also receive the message here and parse in this function
        _clients.put(username, new ClientInfo(url, publicKey, username));
    }

    public void createNewFile(String path, ClientInfo owner, SecretKeySpec fileKey, String initialContent) {
        File file = new File(path);
        _files.add(new FileInfo(file, owner, fileKey));

        try (FileWriter fw = new FileWriter(file)) {
            fw.write(initialContent);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void shareFile(String owner, String clientToShare, String path) {
        FileInfo fileToShare = _files.stream().filter(x -> x.getFile().getPath().equals(path)).findFirst().orElse(null);
        if(fileToShare != null) {
            File file = fileToShare.getFile();

            // Share with user, verify owner
        }
    }

    public void updateFile(String path, String content) {
        FileInfo fileToShare = _files.stream().filter(x -> x.getFile().getPath().equals(path)).findFirst().orElse(null);
        if(fileToShare != null) {
            try (FileWriter fw = new FileWriter(fileToShare.getFile())) {
                fw.write(content);
                fileToShare.updateVersion();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void getFile(String path, String username) {
        // Verify if has access to file
        // Send file
    }

    public void sendFileToBackup(FileInfo fo) {
        // Send fo to backup;
    }

}
