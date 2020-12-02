package sirs.server;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

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

    private String filesRootFolder = "files";


    public ServerThread(ConcurrentHashMap<String, ClientInfo> clients, List<FileInfo> files, char[] password, SSLSocket socket) {
        _clients = clients;
        _files = files;
        _password = password;
        _socket = socket;
        _clients.put("testUser", new ClientInfo(null, null, "testUser", null, null));
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
                        reply = parseCreateFile(operationJson, is);
                        break;
                    case "ShareFile":
                        break;
                    case "UpdateFile":
                        break;
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

    public boolean verifyCredentials(String username, String email) {

        if (_clients.containsKey(username)) {
            if (_clients.get(username).getEmail().equals(email)) { return true; }
            return false;
        }
        return false;
    }

    public boolean matchPasswords(String username, String pw) {

        if (_clients.containsKey(username)) {
            return BCrypt.checkpw(_clients.get(username).getPassword(), pw);
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
        _online = true;
    }

    private JsonObject parseRegister(JsonObject request) {

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
            String email = request.get("email").getAsString();
            String password = request.get("password").getAsString();

            String hashed = BCrypt.hashpw(password, BCrypt.gensalt(12));

            System.out.println(hashed);
            System.out.println(_clients.get(username).getPassword());

            String url = request.get("url").getAsString();

            if (!verifyCredentials(username, email)) {
                reply = JsonParser.parseString("{}").getAsJsonObject();
                reply.addProperty("response", "NOK: Username or Email already in use.");
            }
            else {
                registerClient(url, publicKey, username, email, hashed);
                reply = JsonParser.parseString("{}").getAsJsonObject();
                reply.addProperty("response", "OK");
            }
            return reply;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException |
                IOException | CertificateException | InvalidKeyException |
                SignatureException | KeyStoreException | NoSuchProviderException e) {
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "NOK: " + e.getMessage());
            return reply;
        }
    }

    public void registerClient(String url, PublicKey publicKey, String username, String email, String password) {
        _clients.put(username, new ClientInfo(url, publicKey, username, email, password));
        System.out.println(_clients);
    }


    private JsonObject parseCreateFile(JsonObject request, ObjectInputStream is) { // Can also receive the message here and parse in this function

        JsonObject reply;
        try {
            String username = request.get("username").getAsString();
            if(!_clients.containsKey(username)) {
                // throw new exception
            }

            String fileChecksum = request.get("signature").getAsString();
            byte[] checksum = Base64.getDecoder().decode(fileChecksum);

            // TODO: Change to receive small number of bytes each time

            createNewFile(request.get("path").getAsString(), _clients.get(username), checksum, is);

//            ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
//            byte[] buffer = new byte[8*1024];
//            int readBytes = 0;
//            while(readBytes < fileSize) {
//                int s = is.read(buffer);
//                if (s == -1) break;
//                byteArray.write(buffer, 0, s);
//                readBytes+=s;
//            }
//
//            byte[] content = byteArray.toByteArray();

            // Send file to backup
            reply = JsonParser.parseString("{}").getAsJsonObject();
            reply.addProperty("response", "OK");
            return reply;

        } catch (IOException | ClassNotFoundException e) {
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

        FileInfo fi = new FileInfo(file, owner, checksum);
        fi.addEditor(owner);
        _files.add(fi);

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
        ksTrust.load(new FileInputStream("keys/server.truststore.pk12"), _password);
        return ksTrust.getCertificate("client-ca");
    }

    private byte[] decipherHash(byte[] bytes, PublicKey clientPubKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, clientPubKey);
        return cipher.doFinal(bytes);
    }

    private byte[] hashBytes(byte[] cipheredBytes) throws NoSuchAlgorithmException {
        final String DIGEST_ALGO = "SHA-256";
        MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);
        messageDigest.update(cipheredBytes);
        return messageDigest.digest();
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
                ServerThread st = new ServerThread(_clients, _files, _password, s);
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
            ksTrust.load(new FileInputStream("keys/server.truststore.pk12"), _password);
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


}
