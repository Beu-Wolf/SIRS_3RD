package Client;

public class Main {
    public static void main(String args[]) {

        // receive and print arguments
        System.out.printf("Received %d arguments%n", args.length);
        for (int i = 0; i < args.length; i++) {
            System.out.printf("arg[%d] = %s%n", i, args[i]);
        }

        final String _clientHost = args[0];
        final int _clientPort = Integer.parseInt(args[1]);


        Client client = new Client("localhost", 10000, _clientHost, _clientPort);
        client.interactive();
    }
}
