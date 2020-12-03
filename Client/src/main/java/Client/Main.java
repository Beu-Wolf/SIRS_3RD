package Client;

public class Main {
    public static void main(String args[]) {
        String keysDir = "keys";
        String filesDir = "files";

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
            } else {
                printUsage();
            }
        }

        Client client = new Client("localhost", 10000, filesDir, keysDir);
        client.interactive();
    }

    public static void printUsage() {
        System.err.println("Usage: client [-k keys_folder] [-f files_folder]");
        System.exit(1);
    }
}
