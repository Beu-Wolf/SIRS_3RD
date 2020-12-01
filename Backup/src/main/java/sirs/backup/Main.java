package sirs.backup;

public class Main {
    public static void main(String args[]) {
        String host = "localhost";
        int port = 20000;

        BackupServer server = new BackupServer(host, port);
        server.start();
    }
}