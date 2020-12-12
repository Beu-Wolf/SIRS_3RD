package Client;

public class Main {
    public static void main(String args[]) {
        String keysDir = "keys";
        String filesDir = "files";
        String serverHost = null;

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-k")) {
                if (++i < args.length) {
                    keysDir = args[i];
                } else {
                    printUsage();
                }
            } else if (args[i].equals("-f")) {
                if (++i < args.length) {
                    filesDir = args[i];
                } else {
                    printUsage();
                }
            } else if (serverHost == null) {
                serverHost = args[i];
            } else {
                printUsage();
            }
        }

        if (serverHost == null) {
            serverHost = "localhost";
        }

        Client client = new Client(serverHost, 10000, filesDir, keysDir);

        client.interactive();
    }

    public static void printUsage() {
        System.err.println("Usage: client [server_host] [-k keys_folder] [-f files_folder]");
        System.exit(1);
    }
}
