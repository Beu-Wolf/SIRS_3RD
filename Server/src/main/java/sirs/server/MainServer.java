package sirs.server;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import sirs.server.exceptions.*;


import javax.crypto.*;
import javax.net.ssl.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.mindrot.jbcrypt.BCrypt;



class ServerThread extends Thread {

    private ConcurrentHashMap<String, ClientInfo> _clients;
    private ConcurrentHashMap<String, FileInfo> _files;
    private boolean _online = false;
    private String _loggedInUser;

    private char[] _password;
    private SSLSocket _socket;

    private String _backupHost;
    private SSLSocketFactory _backupSocketFactory;

    private String filesRootFolder = "files";


    public ServerThread(ConcurrentHashMap<String, ClientInfo> clients, ConcurrentHashMap<String, FileInfo> files, char[] password, SSLSocket socket, SSLSocketFactory backupSocketFactory, String backupHost) {
        _clients = clients;
        _files = files;
        _password = password;
        _socket = socket;
        _backupSocketFactory = backupSocketFactory;
        _backupHost = backupHost;
    }

    @Override
    public void run() {
        System.out.println("accepted");
        try {
            ObjectInputStream is = new ObjectInputStream(_socket.getInputStream());
            ObjectOutputStream os = new ObjectOutputStream(_socket.getOutputStream());

            String line;
            boolean exit = false;

            while(!exit ) {
                line = (String) is.readObject();

                JsonObject operationJson = JsonParser.parseString(line).getAsJsonObject();

                JsonObject reply = null;
                String operation = operationJson.get("operation").getAsString();
                switch (operation) {
                    case "RegisterUser":
                        reply = parseRegister(operationJson);
                        break;
                    case "LoginUser":
                        reply = parseLogin(operationJson);
                        break;
                    case "CreateFile":
                        reply = parseCreateFile(operationJson, is, os);
                        break;
                    case "ShareFile":
                        reply = parseShareFile(operationJson, is, os);
                        break;
                    case "EditFile":
                        reply = parseEditFile(operationJson, is, os);
                        break;
                    case "GetFile":
                        reply = parseGetFile(operationJson, is, os);
                        break;
                    case "GetShared":
                        reply = parseGetShared(operationJson, is, os);
                        break;
                    case "RevokeFile":
                        reply = parseRevokeFile(operationJson, is, os);
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
                    os.writeObject(reply.toString());
                    os.flush();
                }
            }
            is.close();
            os.close();
            _socket.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

    }

    public boolean canRegister(String username) {

        if (_clients.containsKey(username)) { return false; }

        return true;
    }

    public boolean matchPasswords(String username, String pw) {

        if (_clients.containsKey(username)) {
            return BCrypt.checkpw(pw, _clients.get(username).getPassword());
        }
        return false;
    }

    private JsonObject parseLogin(JsonObject request) {

        JsonObject reply;

        String username = request.get("username").getAsString();
        String password = request.get("password").getAsString();

        if (!matchPasswords(username, password)) {
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: Wrong Password.");
        }
        else {
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            login(username);
        }
        return reply;
    }

    private void login(String username) {
        _loggedInUser = username;
        _clients.get(username).setUserOnline(true);
    }

    private JsonObject parseRegister(JsonObject request) {

        JsonObject reply;
        try {

            String certString = request.get("cert").getAsString();
            byte[] certBytes = Base64.getDecoder().decode(certString);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            InputStream in = new ByteArrayInputStream(certBytes);
            X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);

            cert.verify(getClientCACert().getPublicKey());

            String username = request.get("username").getAsString();
            String password = request.get("password").getAsString();

            String hashed = BCrypt.hashpw(password, BCrypt.gensalt(12));

            if (!canRegister(username)) {
                reply = JsonParser.parseString("{}").getAsJsonObject();
                reply.addProperty("response", "NOK: Username already in use.");
            }
            else {
                registerClient(cert, username, hashed);
                reply = JsonParser.parseString("{}").getAsJsonObject();
                reply.addProperty("response", "OK");
            }
            return reply;
        } catch (NoSuchAlgorithmException |
                IOException | CertificateException | InvalidKeyException |
                SignatureException | KeyStoreException | NoSuchProviderException e) {
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        }
    }

    public void registerClient(Certificate cert, String username, String password) {
        _clients.put(username, new ClientInfo(cert, username, password));
        _loggedInUser = username;
    }


    private JsonObject parseCreateFile(JsonObject request, ObjectInputStream is, ObjectOutputStream os) {

        JsonObject reply;
        try {
            String username = request.get("username").getAsString();
            if(!_clients.containsKey(username)) {
                throw new NoClientException(username);
            }

            // Compute file path to write to
            //Concatenate username with file path
            Path newFilePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, _clients.get(username).getUsername(), request.get("path").getAsString()).normalize();

            // Path to write temp file in order to check signature
            Path tempFilePath = Paths.get(newFilePath.getParent().toString(), newFilePath.getFileName() + "_createTemp");

            sendAck(os);

            Files.createDirectories(tempFilePath.getParent());

            File file = new File(String.valueOf(tempFilePath));
            file.createNewFile();
            new FileOutputStream(file).close(); // Clean file

            byte[] computedHash = receiveFileFromSocket(file, is);

            sendAck(os);

            // Get client signature
            String line = (String) is.readObject();

            request = JsonParser.parseString(line).getAsJsonObject();

            String fileSignature = request.get("signature").getAsString();
            byte[] signature = Base64.getDecoder().decode(fileSignature);

            byte[] fileHash = decipherHash(signature, _clients.get(username).getPublicKey());

            if (!Arrays.equals(computedHash, fileHash)) {
                throw new InvalidHashException("File Signatures do not match");
            }

            FileInfo fi = createNewFile(tempFilePath, newFilePath, _clients.get(username), signature);

            // Send file to backup
            sendFileToBackup(newFilePath, username, fi, fileSignature);
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;

        } catch (IOException | ClassNotFoundException | NoClientException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidHashException | BackupException | MessageNotAckedException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        }
    }


    public FileInfo createNewFile( Path tempPath, Path newPath, ClientInfo owner, byte[] checksum) throws IOException {

        Files.copy(tempPath, newPath, StandardCopyOption.REPLACE_EXISTING);

        Files.delete(tempPath);

        String path = String.valueOf(newPath);
        File file = new File(path);

        FileInfo fi = new FileInfo(file, owner, checksum, owner);
        fi.addEditor(owner);
        _files.put(path, fi);
        return fi;
    }

    public JsonObject parseEditFile(JsonObject request, ObjectInputStream is, ObjectOutputStream os) {
        JsonObject reply;
        try {
            String username = request.get("username").getAsString();
            if(!_clients.containsKey(username)) {
                throw new NoClientException(username);
            }

            Path filePath;
            if (request.get("ownerEdit").getAsBoolean()) {
                filePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, username, request.get("path").getAsString()).normalize();
            } else {
                filePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, request.get("path").getAsString()).normalize();
            }

            // Verify if file exists
            String pathStr = filePath.toString();
            if(!_files.containsKey(pathStr)) {
                 throw new MissingFileException(pathStr);
            }

            // Verify permission to edit file
            FileInfo fi = _files.get(pathStr);
            if (!fi.containsEditor(_clients.get(username))) {
                throw new InvalidEditorException(username, filePath.toString());
            }

            sendAck(os);

            // Path to write temp file in order to check signature
            Path tempFilePath = Paths.get(filePath.getParent().toString(), filePath.getFileName() + "_editTemp");

            File file = new File(String.valueOf(tempFilePath));
            file.createNewFile();
            new FileOutputStream(file).close(); // Clean file

            byte[] computedHash = receiveFileFromSocket(file, is);

            sendAck(os);

            // Get client signature
            String line = (String) is.readObject();

            request = JsonParser.parseString(line).getAsJsonObject();

            String fileSignature = request.get("signature").getAsString();
            byte[] signature = Base64.getDecoder().decode(fileSignature);

            byte[] fileHash = decipherHash(signature, _clients.get(username).getPublicKey());

            if (!Arrays.equals(computedHash, fileHash)) {
                throw new InvalidHashException("File signatures do not match!");
            }

            editFile(tempFilePath, fi, signature, _clients.get(username));

            sendFileToBackup(filePath, username, fi, fileSignature);

            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;

        } catch (IOException | NoClientException | InvalidEditorException | MissingFileException | ClassNotFoundException | BackupException | NoSuchAlgorithmException | MessageNotAckedException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidHashException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        }
    }

    public void editFile(Path tempFilePath, FileInfo fi, byte[] signature, ClientInfo lastEditor) throws IOException {

        Files.copy(tempFilePath, fi.getFile().toPath(), StandardCopyOption.REPLACE_EXISTING);
        Files.delete(tempFilePath);

        fi.setLatestSignature(signature);
        fi.setLastEditor(lastEditor);
        fi.updateVersion();
    }

    private void sendFileToBackup(Path filePath, String username, FileInfo fi, String fileSignature) throws IOException, ClassNotFoundException, BackupException, MessageNotAckedException {

        SSLSocket connectionToBackup = connectToBackupServer();
        assert connectionToBackup != null;

        ObjectOutputStream bos = new ObjectOutputStream(connectionToBackup.getOutputStream());
        ObjectInputStream bis = new ObjectInputStream(connectionToBackup.getInputStream());

        JsonObject backupRequest = JsonParser.parseString("{}").getAsJsonObject();
        backupRequest.addProperty("operation", "BackupFile");
        backupRequest.addProperty("lastEditor", username);
        backupRequest.addProperty("signature", fileSignature);

        Path backupFilePath = Paths.get(System.getProperty("user.dir"), filesRootFolder).relativize(filePath);
        System.out.println("Backup Path: " + backupFilePath);
        backupRequest.addProperty("path", backupFilePath.toString());

        bos.writeObject(backupRequest.toString());

        ackMessage(bis);

        sendFile(fi, bos);

        bis.close();
        bos.close();

    }

    private void getFileFromBackup(FileInfo tamperedFile) throws IOException, MessageNotAckedException, ClassNotFoundException{
        SSLSocket connectionToBackup = connectToBackupServer();
        assert connectionToBackup != null;

        ObjectOutputStream bos = new ObjectOutputStream(connectionToBackup.getOutputStream());
        ObjectInputStream bis = new ObjectInputStream(connectionToBackup.getInputStream());

        Path backupFilePath = Paths.get(System.getProperty("user.dir"), filesRootFolder).relativize(tamperedFile.getFile().toPath());

        JsonObject backupRequest = JsonParser.parseString("{}").getAsJsonObject();
        backupRequest.addProperty("operation", "RecoverFile");
        backupRequest.addProperty("path", backupFilePath.toString());

        bos.writeObject(backupRequest.toString());

        ackMessage(bis);

        new FileOutputStream(tamperedFile.getFile()).close(); // Clean file
        // Overwrite existent
        receiveFileFromBackupSocket(tamperedFile.getFile(), bis);

        sendAck(bos);

        bis.close();
        bos.close();
    }

    public byte[] receiveFileFromSocket(File file, ObjectInputStream is) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {

        MessageDigest messageDigest = getMessageDigest();

        byte[] fileChunk;
        boolean fileFinish = false;
        while(!fileFinish) {
            fileChunk = (byte[]) is.readObject();
            if (Base64.getEncoder().encodeToString(fileChunk).equals("FileDone")) {
                fileFinish = true;
            } else {
                messageDigest.update(fileChunk, 0, fileChunk.length);
                Files.write(file.toPath(), fileChunk, StandardOpenOption.APPEND);
            }
        }
        return messageDigest.digest();
    }

    private void receiveFileFromBackupSocket(File file, ObjectInputStream is) throws IOException, ClassNotFoundException {
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

    public JsonObject parseShareFile(JsonObject request, ObjectInputStream is, ObjectOutputStream os) {
        JsonObject reply = JsonParser.parseString("{}").getAsJsonObject();
        try {
            String path = request.get("path").getAsString();
            String username = request.get("username").getAsString();

            if (!_clients.containsKey(username)) {
                throw new NoClientException(username);
            }

            Path sharePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, _loggedInUser, path).normalize();

            // Verify if file exists
            String pathStr = sharePath.toString();
            if(!_files.containsKey(pathStr)) {
                throw new MissingFileException(sharePath.toString());
            }

            sendAck(os);

            System.out.println("Sharing: " + sharePath.toString() + " with " + username);

            byte[] keyBytes = _clients.get(username).getPublicKey().getEncoded();
            String encodedKey = Base64.getEncoder().encodeToString(keyBytes);
            JsonObject publicKeyReply = JsonParser.parseString("{}").getAsJsonObject();
            publicKeyReply.addProperty("publicKey", encodedKey);

            os.writeObject(publicKeyReply.toString());

            ackMessage(is);

            JsonObject cipheredKeyJson = JsonParser.parseString((String) is.readObject()).getAsJsonObject();
            byte[] cipheredKey = Base64.getDecoder().decode(cipheredKeyJson.get("cipheredFileKey").getAsString());

            ClientInfo client = _clients.get(username);
            client.shareFile(path, cipheredKey, _loggedInUser);

            _files.get(pathStr).addEditor(client);

            reply.addProperty("response", "OK");
        } catch (Exception e) {
            e.printStackTrace();
            reply.addProperty("response", "NOK: " + e.getMessage());
        }

        return reply;
    }

    public JsonObject parseGetFile(JsonObject request, ObjectInputStream is, ObjectOutputStream os) {
        ClientInfo client = _clients.get(_loggedInUser);
        JsonObject response = JsonParser.parseString("{}").getAsJsonObject();

        try {
            String requestPath = request.get("path").getAsString();

            Path p;
            if (request.get("ownerGet").getAsBoolean()) {
                requestPath = Paths.get(_loggedInUser, requestPath).toString();
            }
            p = Paths.get(System.getProperty("user.dir"), filesRootFolder, requestPath).normalize();

            String path = String.valueOf(p);
            if (!_files.containsKey(path)) {
                throw new MissingFileException(requestPath);
            }

            FileInfo file = _files.get(path);

            if (!file.containsEditor(client)) {
                throw new NoPermissionException(_loggedInUser, requestPath);
            }

            sendAck(os);

            // Verify if file was not tampered with when was in the server (Ransomware)
            byte[] currFileHash  = computeFileSignature(new FileInputStream(file.getFile()));

            byte[] fileHash = decipherHash(file.getLatestSignature(), file.getLastEditor().getPublicKey());

            if(!Arrays.equals(currFileHash, fileHash)) {
                // Someone tampered with the file, recover it
                System.out.println("Recovering file!");
                getFileFromBackup(file);
            }

            sendFile(file.getFile(), os);

            ackMessage(is);

            response.addProperty("response", "OK");
        } catch (Exception e) {
            e.printStackTrace();
            response.addProperty("response", "NOK: " + e.getMessage());
        }

        return response;
    }

    public void sendFile(File file, ObjectOutputStream os) throws IOException {
        FileInputStream fis = new FileInputStream(file.getPath());

        byte[] chunk = new byte[8 * 1024];
        int bytesRead;
        while ((bytesRead = fis.read(chunk)) >= 0) {
            os.writeObject(Arrays.copyOfRange(chunk, 0, bytesRead));
            os.flush();
        }
        os.writeObject(Base64.getDecoder().decode("FileDone"));
        os.flush();
    }

    public JsonObject parseGetShared(JsonObject request, ObjectInputStream is, ObjectOutputStream os) {
        ClientInfo client = _clients.get(_loggedInUser);
        JsonObject response = JsonParser.parseString("{}").getAsJsonObject();

        JsonArray fileArray = JsonParser.parseString("[]").getAsJsonArray();

        for (SharedFile f : client.getSharedFiles()) {
            JsonObject obj = JsonParser.parseString("{}").getAsJsonObject();
            obj.addProperty("path", f.getPath());
            obj.addProperty("owner", f.getOwner());
            obj.addProperty("cipheredKey", Base64.getEncoder().encodeToString(f.getCipheredKey()));

            fileArray.add(obj);
        }

        response.add("files", fileArray);
        return response;
    }

    public JsonObject parseRevokeFile(JsonObject request, ObjectInputStream is, ObjectOutputStream os) {
        JsonObject reply = JsonParser.parseString("{}").getAsJsonObject();
        try {
            String path = request.get("path").getAsString();
            String username = request.get("username").getAsString();

            if (username.equals(_loggedInUser)) {
                throw new SelfRevokeException(username, path);
            }

            if (!_clients.containsKey(username)) {
                throw new NoClientException(username);
            }
            ClientInfo client = _clients.get(username);

            Path revokePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, _loggedInUser, path).normalize();

            // Verify if file exists
            String pathStr = revokePath.toString();
            if (!_files.containsKey(pathStr)) {
                throw new MissingFileException(revokePath.toString());
            }

            FileInfo file = _files.get(pathStr);
            if (!file.containsEditor(client)) {
                throw new NotAnEditorException(username, path);
            }

            sendAck(os);

            client.revokeFile(path, _loggedInUser);
            file.removeEditor(client);

            JsonObject createFileRequest = JsonParser.parseString((String) is.readObject()).getAsJsonObject();
            JsonObject createFileReply = parseCreateFile(createFileRequest, is, os);
            os.writeObject(createFileReply.toString());

            JsonArray editorsJson = JsonParser.parseString("[]").getAsJsonArray();
            for (ClientInfo editor : file.getEditors()) {
                if (editor.getUsername().equals(_loggedInUser)) continue;
                editorsJson.add(editor.getUsername());
            }
            os.writeObject(editorsJson.toString());
            ackMessage(is);

            for (ClientInfo editor : file.getEditors()) {
                if (editor.getUsername().equals(_loggedInUser)) continue;
                JsonObject shareFileRequest = JsonParser.parseString((String) is.readObject()).getAsJsonObject();
                JsonObject shareFileReply = parseShareFile(shareFileRequest, is, os);
                os.writeObject(shareFileReply.toString());
            }

            reply.addProperty("response", "OK");
        } catch (Exception e) {
            e.printStackTrace();
            reply.addProperty("response", "NOK: " + e.getMessage());
        }

        return reply;
    }

    public void sendFile(FileInfo fo, ObjectOutputStream os) throws IOException {
        try (FileInputStream fis = new FileInputStream(fo.getFile())) {

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


    private Certificate getClientCACert() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ksTrust = KeyStore.getInstance("PKCS12");
        ksTrust.load(new FileInputStream("keys/server_client.truststore.pk12"), _password);
        return ksTrust.getCertificate("client-ca");
    }

    private byte[] decipherHash(byte[] bytes, PublicKey clientPubKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, clientPubKey);
        return cipher.doFinal(bytes);
    }


    private MessageDigest getMessageDigest() throws NoSuchAlgorithmException {
        final String DIGEST_ALGO = "SHA-256";
        return MessageDigest.getInstance(DIGEST_ALGO);
    }

    private byte[] computeFileSignature(FileInputStream fis) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Compute checksum of this File
        MessageDigest messageDigest = getMessageDigest();
        byte[] fileChunk = new byte[8*1024];
        int count;
        while ((count = fis.read(fileChunk)) != -1) {
            messageDigest.update(fileChunk, 0, count);
        }

        return messageDigest.digest();
    }

    private void sendAck(ObjectOutputStream os) throws IOException {
        JsonObject reply = JsonParser.parseString("{}").getAsJsonObject();
        reply.addProperty("response", "OK");

        os.writeObject(reply.toString());
    }

    private boolean ackMessage(ObjectInputStream is) throws IOException, ClassNotFoundException, MessageNotAckedException {
        String line;
        line = (String) is.readObject();

        JsonObject reply = JsonParser.parseString(line).getAsJsonObject();
        if (!reply.get("response").getAsString().equals("OK")) {
            throw new MessageNotAckedException("Error: " + reply.get("response").getAsString());
        }
        return true;
    }

    private SSLSocket connectToBackupServer() {
        try {
            SSLSocket s = (SSLSocket) _backupSocketFactory.createSocket(_backupHost, 20000);
            String[] protocols = new String[]{"TLSv1.3"};
            String[] cipherSuites = new String[]{"TLS_AES_128_GCM_SHA256"};

            s.setEnabledProtocols(protocols);
            s.setEnabledCipherSuites(cipherSuites);
            s.startHandshake();
            return s;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}



public class MainServer {

    private ConcurrentHashMap<String, ClientInfo> _clients = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, FileInfo> _files = new ConcurrentHashMap<>();

    private String _host;
    private int _port;
    private char[] _password;
    private String _backupHost;

    public MainServer(String host, int port, String backupHost) {
        _host = host;
        _port = port;
        _password = "changeit".toCharArray();
        _backupHost = backupHost;
    }

    public void start() {
        SSLServerSocketFactory ssl = getServerSocketFactory();
        SSLSocketFactory backupSocketFactory = getBackupSocketFactory();

        assert ssl != null;
        try(SSLServerSocket socket = (SSLServerSocket) ssl.createServerSocket(_port)) {
            String[] protocols = new String[] {"TLSv1.3"};
            String[] cipherSuites = new String[] {"TLS_AES_128_GCM_SHA256"};
            socket.setEnabledProtocols(protocols);
            socket.setNeedClientAuth(true);
            socket.setEnabledCipherSuites(cipherSuites);

            System.out.println("Running at " + _host + ":" + _port);

            File serverObj = new File("tmp/server.ser");

            if (serverObj.exists()) {
                ObjectInputStream inServer;
                try (FileInputStream serverServerIn = new FileInputStream("tmp/server.ser")) {
                    inServer = new ObjectInputStream(serverServerIn);

                    SerializationWrapper serializationWrapper = (SerializationWrapper) inServer.readObject();

                    _clients = serializationWrapper.getClients();
                    _files = serializationWrapper.getFiles();
                }

            }

            while (true) {
                SSLSocket s = (SSLSocket) socket.accept();
                ServerThread st = new ServerThread(_clients, _files, _password, s, backupSocketFactory, _backupHost);
                st.start();
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    ConcurrentHashMap<String, ClientInfo> getClients() { return  _clients;}

    ConcurrentHashMap<String, FileInfo> getFileInfo() { return _files; }

    private SSLServerSocketFactory getServerSocketFactory() {
        SSLServerSocketFactory ssf;
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            KeyStore ks = KeyStore.getInstance("PKCS12");

            ks.load(new FileInputStream("keys/server.keystore.pk12"), _password);
            kmf.init(ks, _password);

            KeyStore ksTrust = KeyStore.getInstance("PKCS12");
            ksTrust.load(new FileInputStream("keys/server_client.truststore.pk12"), _password);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ksTrust);

            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            ssf = ctx.getServerSocketFactory();
            return ssf;
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException | UnrecoverableKeyException | KeyManagementException e) {
            e.printStackTrace();
        }
        return null;
    }

    private SSLSocketFactory getBackupSocketFactory() {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            KeyStore ks = KeyStore.getInstance("PKCS12");

            ks.load(new FileInputStream("keys/server.keystore.pk12"), _password);
            kmf.init(ks, _password);

            KeyStore ksTrust = KeyStore.getInstance("PKCS12");
            ksTrust.load(new FileInputStream("keys/server_backup.truststore.pk12"), _password);
            TrustManagerFactory tm = TrustManagerFactory.getInstance("SunX509");
            tm.init(ksTrust);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tm.getTrustManagers(), null);

            return sslContext.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
