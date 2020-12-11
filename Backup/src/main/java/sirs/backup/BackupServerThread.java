package sirs.backup;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import sirs.backup.exceptions.MessageNotAckedException;
import sirs.backup.exceptions.MissingFileException;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

public class BackupServerThread extends Thread {
    private Socket _socket;

    private HashMap<String, BackupFileInfo> _files;
    private String filesRootFolder = "files";

    public BackupServerThread(HashMap<String, BackupFileInfo> files,  Socket socket) {
        _files = files;
        _socket = socket;
    }

    @Override
    public void run() {
        System.out.println("Starting backup server thread!");
        try {
            ObjectInputStream is = new ObjectInputStream(_socket.getInputStream());
            ObjectOutputStream os = new ObjectOutputStream(_socket.getOutputStream());

            String line = (String) is.readObject();
            System.out.println("read: " + line);

            JsonObject operationJson = JsonParser.parseString(line).getAsJsonObject();

            JsonObject reply = null;
            String operation = operationJson.get("operation").getAsString();
            switch (operation) {
                case "BackupFile":
                    reply = parseBackupFile(operationJson, is, os);
                    break;
                case "RecoverFile":
                    reply = parseRecoverFile(operationJson, is, os);
                    break;
                default:
                    throw new IOException("Invalid operation");
            }
            if (reply != null) {
                System.out.println("Sending: " + reply);
                os.writeObject(reply.toString());
            }

            is.close();
            os.close();
            _socket.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /* Takes a file from the server and stores it */
    private JsonObject parseBackupFile(JsonObject request, ObjectInputStream is, ObjectOutputStream os) {
        JsonObject reply;
        try {

            Path filePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, request.get("path").getAsString());
            System.out.println("FilePath: " + filePath);

            // Write file
            Files.createDirectories(filePath.getParent());

            File file = new File(String.valueOf(filePath));
            file.createNewFile();

            // Get signature
            String fileSignature = request.get("signature").getAsString();
            byte[] signature = Base64.getDecoder().decode(fileSignature);

            sendAck(os);

            receiveFileFromSocket(file, is);

            _files.put(request.get("path").getAsString(), new BackupFileInfo(file, request.get("lastEditor").getAsString(), signature));

            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK" + e.getMessage());
            return reply;
        }


    }

    /* Gives back the file to the requesting server */
    private JsonObject parseRecoverFile(JsonObject request, ObjectInputStream is, ObjectOutputStream os) {
        JsonObject reply;
        try {
            String pathstr = request.get("path").getAsString();
           if(!_files.containsKey(pathstr)) {
               throw new MissingFileException(pathstr);
           }

           sendAck(os);
           sendFileToSocket(_files.get(pathstr).getFile(), os);
           ackMessage(is);

        } catch (MissingFileException | IOException | ClassNotFoundException | MessageNotAckedException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK" + e.getMessage());
            return reply;
        }
        return null;
    }

    private void receiveFileFromSocket(File file, ObjectInputStream is) throws IOException, ClassNotFoundException {
        byte[] fileChunk;
        boolean fileFinish = false;
        while(!fileFinish) {
            fileChunk = (byte[]) is.readObject();
            if (Base64.getEncoder().encodeToString(fileChunk).equals("FileDone")) {
                fileFinish = true;
            } else {
                Files.write(file.toPath(), fileChunk, StandardOpenOption.APPEND);
            }
        }
    }

    private void sendFileToSocket(File file, ObjectOutputStream os) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {

            byte[] fileChunk = new byte[8 * 1024];
            int bytesRead;

            while ((bytesRead = fis.read(fileChunk)) >= 0) {
                os.writeObject(Arrays.copyOfRange(fileChunk, 0, bytesRead));
                os.flush();
            }
            os.writeObject(Base64.getDecoder().decode("FileDone"));
            os.flush();
        }
    }

    private void sendAck(ObjectOutputStream os) throws IOException {
        JsonObject reply = JsonParser.parseString("{}").getAsJsonObject();
        reply.addProperty("response", "OK");

        os.writeObject(reply.toString());
    }

    private boolean ackMessage(ObjectInputStream is) throws IOException, ClassNotFoundException, MessageNotAckedException {
        String line;
        System.out.println("Waiting");
        line = (String) is.readObject();

        System.out.println("Received:" + line);
        JsonObject reply = JsonParser.parseString(line).getAsJsonObject();
        if (!reply.get("response").getAsString().equals("OK")) {
            throw new MessageNotAckedException("Error: " + reply.get("response").getAsString());
        }
        return true;
    }

}
