package sirs.server;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import sirs.server.exceptions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
    private List<FileInfo> _files;
    private boolean _online = false;

    private char[] _password;
    private SSLSocket _socket;

    private SSLSocketFactory _backupSocketFactory;

    private String filesRootFolder = "files";


    public ServerThread(ConcurrentHashMap<String, ClientInfo> clients, List<FileInfo> files, char[] password, SSLSocket socket, SSLSocketFactory backupSocketFactory) {
        _clients = clients;
        _files = files;
        _password = password;
        _socket = socket;
        _backupSocketFactory = backupSocketFactory;
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
                System.out.println("read: " + line);

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
                        break;
                    case "EditFile":
                        reply = parseEditFile(operationJson, is, os);
                        break;
                    case "GetFile":
                        break;
                    case "RecoverFile":
                        reply = parseRecoverFile(operationJson, os);
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
            login(username);
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
        }
        return reply;
    }

    private void login(String username) {
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

            System.out.println(hashed);

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
        System.out.println(_clients);
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
            System.out.println("Computed Signature = " + Base64.getEncoder().encodeToString(computedHash));

            sendAck(os);

            // Get client signature
            String line = (String) is.readObject();
            System.out.println("read: " + line);

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

        File file = new File(String.valueOf(newPath));

        FileInfo fi = new FileInfo(file, owner, checksum);
        fi.addEditor(owner);
        _files.add(fi);
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
            FileInfo fi = _files.stream().filter(x -> x.getFile().toPath().equals(filePath)).findFirst().orElse(null);
            if(fi == null) {
                 throw new MissingFileException(filePath.toString());
            }

            // Verify permission to edit file
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
            System.out.println("Computed Signature = " + Base64.getEncoder().encodeToString(computedHash));

            sendAck(os);

            // Get client signature
            String line = (String) is.readObject();
            System.out.println("read: " + line);

            request = JsonParser.parseString(line).getAsJsonObject();

            String fileSignature = request.get("signature").getAsString();
            byte[] signature = Base64.getDecoder().decode(fileSignature);

            byte[] fileHash = decipherHash(signature, _clients.get(username).getPublicKey());

            if (!Arrays.equals(computedHash, fileHash)) {
                throw new InvalidHashException("File signatures do not match!");
            }

            editFile(tempFilePath, fi, signature);

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

    public void editFile(Path tempFilePath, FileInfo fi, byte[] signature) throws IOException {

        Files.copy(tempFilePath, fi.getFile().toPath(), StandardCopyOption.REPLACE_EXISTING);
        Files.delete(tempFilePath);

        fi.setLatestSignature(signature);
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
        backupRequest.addProperty("version", fi.getCurrentVersion());
        backupRequest.addProperty("signature", fileSignature);




        Path backupFilePath = Paths.get(System.getProperty("user.dir"), filesRootFolder).relativize(filePath);
        System.out.println("Backup Path: " + backupFilePath);
        backupRequest.addProperty("path", backupFilePath.toString());

        System.out.println(backupRequest.toString());
        bos.writeObject(backupRequest.toString());

        ackMessage(bis);

        sendFile(fi, bos);

        ackMessage(bis);

        bis.close();
        bos.close();

    }

    public JsonObject parseRecoverFile(JsonObject request, ObjectOutputStream os) {
        /*JsonObject reply;
        try {
            String username = request.get("username").getAsString();

            // Verify if has acess to file
            if(!_clients.containsKey(username)) {
                throw new NoClientException(username);
            }

            // compute wanted path
            Path filePath;
            Path backupFilePath;
            if (request.get("ownedFile").getAsBoolean()) {
                filePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, username, request.get("path").getAsString()).normalize();
                backupFilePath = Paths.get(username, request.get("path").getAsString());
            } else {
                filePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, request.get("path").getAsString()).normalize();
                backupFilePath = Paths.get(request.get("path").getAsString());
            }
            System.out.println("filePath: " + backupFilePath);

            // Verify if file exists
            FileInfo fi = _files.stream().filter(x -> x.getFile().toPath().equals(filePath)).findFirst().orElse(null);
            if(fi == null) {
                throw new MissingFileException(filePath.toString());
            }

            // Verify permission to edit file
            if (!fi.containsEditor(_clients.get(username))) {
                throw new InvalidEditorException(username, filePath.toString());
            }

            // Clean File
            new FileOutputStream(fi.getFile()).close();

            // get file from backup
            JsonObject backupReply = receiveFileFromBackup(backupFilePath, fi);

            if (!backupReply.get("response").getAsString().equals("OK")) {
                // Someting went wrong
                throw new BackupException("Could not get file from backup");
            }

            // Send file to client
            JsonObject confirmation = JsonParser.parseString("{}").getAsJsonObject();
            confirmation.addProperty("response",  "SendingFile");

            os.writeObject(confirmation.toString());
            sendFile(fi, os);
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response" , "OK");
            return reply;

        } catch (IOException | NoClientException | InvalidEditorException | MissingFileException | ClassNotFoundException | NoSuchAlgorithmException | BackupException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        } */
        return null;
    }

    private JsonObject receiveFileFromBackup(Path filePath, FileInfo fi) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        SSLSocket connectionToBackup = connectToBackupServer();
        assert connectionToBackup != null;

        ObjectOutputStream bos = new ObjectOutputStream(connectionToBackup.getOutputStream());
        ObjectInputStream bis = new ObjectInputStream(connectionToBackup.getInputStream());

        JsonObject backupRequest = JsonParser.parseString("{}").getAsJsonObject();
        backupRequest.addProperty("operation", "RestoreFile");
        backupRequest.addProperty("path", filePath.toString());

        System.out.println(backupRequest.toString());
        bos.writeObject(backupRequest.toString());

        String line = (String) bis.readObject();
        // Read if successfull
        System.out.println("Received:" + line);

        JsonObject reply = JsonParser.parseString(line).getAsJsonObject();

        if (!reply.get("response").getAsString().equals("sendingFile")) {
            // Someting went wrong, return
            return reply;
        }

        receiveFileFromSocket(fi.getFile(), bis);

        line = (String) bis.readObject();
        // Read if successfull
        System.out.println("Received:" + line);

        reply = JsonParser.parseString(line).getAsJsonObject();

        return reply;
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


    public void shareFile(String owner, String clientToShare, String path) {
        FileInfo fileToShare = _files.stream().filter(x -> x.getFile().getPath().equals(path)).findFirst().orElse(null);
        if(fileToShare != null) {
            File file = fileToShare.getFile();

            // Share with user, verify owner
        }
    }

    public void updateFile(String path, String content) {
        FileInfo fileToShare = _files.stream().filter(x -> x.getFile().getPath().equals(path)).findFirst().orElse(null);
        if(fileToShare != null) {
            try (FileWriter fw = new FileWriter(fileToShare.getFile())) {
                fw.write(content);
                fileToShare.updateVersion();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void getFile(String path, String username) {
        // Verify if has access to file
        // Send file
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

    private SSLSocket connectToBackupServer() {
        try {
            SSLSocket s = (SSLSocket) _backupSocketFactory.createSocket("localhost", 20000);
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

    private void ackMessage(ObjectInputStream is) throws IOException, ClassNotFoundException, MessageNotAckedException {
        String line;
        System.out.println("Waiting");
        line = (String) is.readObject();

        System.out.println("Received:" + line);
        JsonObject reply = JsonParser.parseString(line).getAsJsonObject();
        if (!reply.get("response").getAsString().equals("OK")) {
            throw new MessageNotAckedException("Error: " + reply.get("response").getAsString());
        }
    }

}



public class MainServer {

    private ConcurrentHashMap<String, ClientInfo> _clients = new ConcurrentHashMap<>();
    private List<FileInfo> _files = Collections.synchronizedList(new ArrayList<>());

    private String _host;
    private int _port;
    private char[] _password;

    public MainServer(String host, int port) {
        _host = host;
        _port = port;
        _password = "changeit".toCharArray();

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

            while (true) {
                SSLSocket s = (SSLSocket) socket.accept();
                ServerThread st = new ServerThread(_clients, _files, _password, s, backupSocketFactory);
                st.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

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
