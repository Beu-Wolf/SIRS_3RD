package Client;

public class Main {
    public static void main(String args[]) {
        Client client = new Client("localhost", 10000);
        client.interactive();
    }
}
