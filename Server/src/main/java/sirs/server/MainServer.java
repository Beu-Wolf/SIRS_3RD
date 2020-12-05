package sirs.server;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import sirs.server.exceptions.InvalidEditorException;
import sirs.server.exceptions.MissingFileException;
import sirs.server.exceptions.NoClientException;

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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
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
        _clients.put("testUser", new ClientInfo(null, "testUser", null));
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
                    case "GetFile":
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

            byte[] computedSignature = receiveFileFromSocket(file, is);
            System.out.println("Computed Signature = " + Base64.getEncoder().encodeToString(computedSignature));

            sendAck(os);

            // Get client signature
            String line = (String) is.readObject();
            System.out.println("read: " + line);

            request = JsonParser.parseString(line).getAsJsonObject();

            String fileSignature = request.get("signature").getAsString();
            byte[] signature = Base64.getDecoder().decode(fileSignature);

            //signature = decipherHash(signature, _clients.get(username).getPublicKey());

            /*if (!Arrays.equals(computedSignature, signature)) {
                throw new exception
            }*/

            createNewFile(tempFilePath, newFilePath, _clients.get(username), signature);

            // Send file to backup
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;

        } catch (IOException | ClassNotFoundException | NoClientException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        }
    }



    public void createNewFile( Path tempPath, Path newPath, ClientInfo owner, byte[] checksum) throws IOException {

        Files.copy(tempPath, newPath, StandardCopyOption.REPLACE_EXISTING);

        Files.delete(tempPath);

        File file = new File(String.valueOf(newPath));

        FileInfo fi = new FileInfo(file, owner, checksum);
        fi.addEditor(owner);
        _files.add(fi);

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

            byte[] computedSignature = receiveFileFromSocket(file, is);
            System.out.println("Computed Signature = " + Base64.getEncoder().encodeToString(computedSignature));

            sendAck(os);

            // Get client signature
            String line = (String) is.readObject();
            System.out.println("read: " + line);

            request = JsonParser.parseString(line).getAsJsonObject();

            String fileSignature = request.get("signature").getAsString();
            byte[] signature = Base64.getDecoder().decode(fileSignature);

            //signature = decipherHash(signature, _clients.get(username).getPublicKey());

            /*if (!Arrays.equals(computedSignature, signature)) {
                throw new exception
            }*/

            // TODO: Change to receive small number of bytes each time

            // Clean File
            editFile(tempFilePath, fi, signature);

            // Send file to backup
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;

        } catch (IOException | NoClientException | InvalidEditorException | MissingFileException | ClassNotFoundException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        }
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



    public void editFile(Path tempFilePath, FileInfo fi, byte[] signature) throws IOException {
        Files.copy(tempFilePath, fi.getFile().toPath(), StandardCopyOption.REPLACE_EXISTING);
        Files.delete(tempFilePath);
        fi.setLatestSignature(signature);
        fi.updateVersion();
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

    public void sendFileToBackup(FileInfo fo) {
        // Send fo to backup;
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
        // Compute checksum of this File and cipher with Private Key
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
