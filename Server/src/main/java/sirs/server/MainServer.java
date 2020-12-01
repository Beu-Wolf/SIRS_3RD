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
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


class ServerThread extends Thread {

    private ConcurrentHashMap<String, ClientInfo> _clients;
    private List<FileInfo> _files;

    private char[] _password;
    private SSLSocket _socket;

    private SSLSocketFactory _backupSocketFactory;

    private String filesRootFolder = "files";


    public ServerThread(ConcurrentHashMap<String, ClientInfo> clients, List<FileInfo> files, char[] password, SSLSocket socket, SSLSocketFactory backupSocketFactory) {
        _clients = clients;
        _files = files;
        _password = password;
        _socket = socket;
        _clients.put("testUser", new ClientInfo(null, null, "testUser"));
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
                        reply = parseReceiveUserKey(operationJson);
                        break;
                    case "CreateFile":
                        reply = parseCreateFile(operationJson, is);
                        break;
                    case "ShareFile":
                        break;
                    case "EditFile":
                        reply = parseEditFile(operationJson, is);
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

    private JsonObject parseReceiveUserKey(JsonObject request) {

        JsonObject reply;
        try {
            // Extract public key
            String publicKeyString = request.get("pub_key").getAsString();
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            // verify if public key is signed by the trusted CA
            Certificate ca = getClientCACert();
            ca.verify(publicKey);

            String username = request.get("username").getAsString();
            String url = request.get("url").getAsString();
            receiveUserKey(url, publicKey, username);
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException |
                IOException | CertificateException | InvalidKeyException |
                SignatureException | KeyStoreException | NoSuchProviderException e) {
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        }
    }


    public void receiveUserKey(String url, PublicKey publicKey, String username) { // Can also receive the message here and parse in this function
        _clients.put(username, new ClientInfo(url, publicKey, username));
    }


    private JsonObject parseCreateFile(JsonObject request, ObjectInputStream is) {

        JsonObject reply;
        try {
            String username = request.get("username").getAsString();
            if(!_clients.containsKey(username)) {
                throw new NoClientException(username);
            }

            String fileChecksum = request.get("signature").getAsString();
            byte[] checksum = Base64.getDecoder().decode(fileChecksum);

            // TODO: Change to receive small number of bytes each time

            createNewFile(request.get("path").getAsString(), _clients.get(username), checksum, is);

            // Send file to backup
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;

        } catch (IOException | ClassNotFoundException | NoClientException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        }
    }

    public void createNewFile(String path, ClientInfo owner, byte[] checksum, ObjectInputStream is) throws IOException, ClassNotFoundException {

        //Concatenate username with file path
        Path newFilePath = Paths.get(System.getProperty("user.dir"), filesRootFolder, owner.getUsername(), path).normalize();

        Files.createDirectories(newFilePath.getParent());

        File file = new File(String.valueOf(newFilePath));
        file.createNewFile();
        new FileOutputStream(file).close(); // Clean file

        receiveFileFromSocket(file, is);

        FileInfo fi = new FileInfo(file, owner, checksum);
        fi.addEditor(owner);
        _files.add(fi);

    }

    public JsonObject parseEditFile(JsonObject request, ObjectInputStream is) {
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

            String fileChecksum = request.get("signature").getAsString();
            byte[] checksum = Base64.getDecoder().decode(fileChecksum);

            // TODO: Change to receive small number of bytes each time

            // Clean File
            new FileOutputStream(fi.getFile()).close();
            receiveFileFromSocket(fi.getFile(), is);
            editFile(fi, checksum);

            // Send to backup
            // Send file to backup
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;

        } catch (IOException | NoClientException | InvalidEditorException | MissingFileException | ClassNotFoundException e) {
            e.printStackTrace();
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        }
    }

    public void receiveFileFromSocket(File file, ObjectInputStream is) throws IOException, ClassNotFoundException {
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



    public void editFile(FileInfo fi, byte[] checksum) {
        fi.setLatestChecksum(checksum);
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
