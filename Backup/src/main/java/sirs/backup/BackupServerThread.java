package sirs.backup;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import sirs.backup.exceptions.MissingFileException;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;

public class BackupServerThread extends Thread {
    private Socket _socket;

    private List<BackupFileInfo> _files;
    private String filesRootFolder = "files";

    public BackupServerThread(List<BackupFileInfo> files,  Socket socket) {
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
                    reply = parseBackupFile(operationJson, is);
                    break;
                case "RestoreFile":
                    reply = parseRestoreFile(operationJson, os);
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
    private JsonObject parseBackupFile(JsonObject request, ObjectInputStream is) {
        JsonObject reply;
        try {

            // File schema = ../files/(same as Server)/filename_version
            Path filePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, request.get("path").getAsString() + "_" + request.get("version"));
            System.out.println("FilePath: " + filePath);

            // Write file
            Files.createDirectories(filePath.getParent());

            File file = new File(String.valueOf(filePath));
            file.createNewFile();
            receiveFileFromSocket(file, is);

            // Get signature
            String fileSignature = request.get("signature").getAsString();
            byte[] signature = Base64.getDecoder().decode(fileSignature);

            _files.add(new BackupFileInfo(file, request.get("path").getAsString(), request.get("lastEditor").getAsString(), signature, request.get("version").getAsInt()));

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
    private JsonObject parseRestoreFile(JsonObject request, ObjectOutputStream os) {
        JsonObject reply;
        try {
            // get wanted file (last file)
            BackupFileInfo latestFile;
            if (_files.stream().anyMatch(x -> x.getFileServerPath().equals(request.get("path").getAsString()))) {
                latestFile = _files.stream().filter(x -> x.getFileServerPath().equals(request.get("path").getAsString())).sorted(Comparator.comparingInt(BackupFileInfo::getVersion)).reduce((first, second) -> second).get();
            } else {
                throw new MissingFileException("No file to recover!");
            }

            JsonObject confirmation = JsonParser.parseString("{}").getAsJsonObject();
            confirmation.addProperty("response",  "sendingFile");
            confirmation.addProperty("signature", Base64.getEncoder().encodeToString(latestFile.getSignature()));
            confirmation.addProperty("editor", latestFile.getEditor());

            os.writeObject(confirmation.toString());

            sendFileToSocket(latestFile.getFile(), os);
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;

        } catch (MissingFileException | IOException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK" + e.getMessage());
            return reply;
        }
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

}
