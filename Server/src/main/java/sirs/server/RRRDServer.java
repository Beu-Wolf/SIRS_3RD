package sirs.server;

public class RRRDServer {

    public static void main(String[] args){
        String host = "localhost";
        int port = 10000;

        MainServer server = new MainServer(host, port);
        server.start();

    }
}
