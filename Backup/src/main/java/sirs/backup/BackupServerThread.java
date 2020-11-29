package sirs.backup;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class BackupServerThread extends Thread {
    private Socket _socket;

    public BackupServerThread(Socket socket) {
        _socket = socket;
    }

    @Override
    public void run() {
        System.out.println("Starting backup server thread!");
        try {
            ObjectInputStream is = new ObjectInputStream(_socket.getInputStream());
            ObjectOutputStream os = new ObjectOutputStream(_socket.getOutputStream());

            String line;
            boolean exit = false;

            while(!exit) {
                line = (String) is.readObject();
                System.out.println("read: " + line);
                exit = true;
                if (exit) continue; /* TODO REMOVE */

                JsonObject operationJson = JsonParser.parseString(line).getAsJsonObject();

                JsonObject reply = null;
                String operation = operationJson.get("operation").getAsString();
                switch (operation) {
                    case "BackupFile":
                        reply = parseBackupFile(operationJson, is);
                        break;
                    case "RestoreFile":
                        reply = parseRestoreFile(operationJson, os);
                        break;
                    case "Exit":
                        (reply = JsonParser.parseString("{}").getAsJsonObject()).addProperty("response", "OK");
                        exit = true;
                        break;
                    default:
                        throw new IOException("Invalid operation");
                }
                if (!exit) {
                    assert reply != null;
                    System.out.println("Sending: " + reply);
                    os.writeObject(reply.toString());
                }
            }
            is.close();
            os.close();
            _socket.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /* Takes a file from the server and stores it */
    private JsonObject parseBackupFile(JsonObject request, ObjectInputStream is) { return null; }

    /* Gives back the file to the requesting server */
    private JsonObject parseRestoreFile(JsonObject request, ObjectOutputStream os) { return null; }

}
