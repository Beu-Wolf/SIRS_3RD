package Client;

import Client.exceptions.InvalidPathException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.*;
import javax.net.ssl.*;
import java.io.*;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.Pattern;

public class Client {

    private String _username = "testUser"; // change this to be defined when registering/logging in
    private String _serverHost;
    private int _serverPort;
    private String _filesDir;
    private String _keysDir;
    SSLSocket _currentConnectionSocket;
    private char[] _keyStorePass = "changeit".toCharArray();

    public Client(String serverHost, int serverPort, String filesDir, String keysDir) {
        _serverHost = serverHost;
        _serverPort = serverPort;
        _filesDir = filesDir;
        _keysDir = keysDir;
    }

    public void interactive() {
        Console clientConsole = System.console();
        try {
            connectToServer();
            ObjectOutputStream os = new ObjectOutputStream(_currentConnectionSocket.getOutputStream());
            ObjectInputStream is = new ObjectInputStream(_currentConnectionSocket.getInputStream());
            while(true) {
                System.out.print("> ");

                    String command = clientConsole.readLine().trim();
                    if (Pattern.matches("^exit$", command)) {
                        parseExit(os, is);
                        if(_currentConnectionSocket != null) {
                            _currentConnectionSocket.close();
                        }
                        break;
                    } else if (Pattern.matches("^register$", command)) {
                        parseRegister(clientConsole, os, is);
                    } else if (Pattern.matches("^login$", command)) {
                        parseLogin(clientConsole, os, is);
                    } else if(Pattern.matches("^create file$", command)) {
                        parseCreateFile(clientConsole, os, is);
                    }


            }
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | KeyManagementException | ClassNotFoundException e) {
            e.printStackTrace();
        }

    }
    public void parseLogin(Console clientConsole, ObjectOutputStream os, ObjectInputStream is) throws IOException, ClassNotFoundException {

        System.out.print("Please enter your username: ");
        String username = clientConsole.readLine().trim();
        System.out.print("Please enter your password: ");
        String password = String.valueOf(clientConsole.readPassword());

        login(username, password, os, is);
    }

    public void login(String username, String password, ObjectOutputStream os, ObjectInputStream is) throws IOException, ClassNotFoundException {

        JsonObject request = JsonParser.parseString("{}").getAsJsonObject();
        request.addProperty("operation", "LoginUser");
        request.addProperty("username", username);
        request.addProperty("password", password);

        System.out.println(request.toString());
        os.writeObject(request.toString());

        String line = (String) is.readObject();

        System.out.println("Received:" + line);

        JsonObject reply = JsonParser.parseString(line).getAsJsonObject();
        System.out.println("Result: " + reply.get("response").getAsString());
    }

    public void parseRegister(Console clientConsole, ObjectOutputStream os, ObjectInputStream is) throws IOException, KeyStoreException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException {
        System.out.print("Please enter your username: ");
        String username = clientConsole.readLine().trim();
        System.out.print("Please enter your password: ");
        String pw1 = String.valueOf(clientConsole.readPassword());
        System.out.print("Please re-enter your password to confirm: ");
        String pw2 = String.valueOf(clientConsole.readPassword());
        if (!pw1.equals(pw2)) {
            System.out.println("Passwords don't match");
        }
        else {
            register(username, pw1, os, is);
        }
    }

    public void register(String username, String password, ObjectOutputStream os, ObjectInputStream is) throws KeyStoreException, IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException {

        JsonObject request = JsonParser.parseString("{}").getAsJsonObject();
        request.addProperty("operation", "RegisterUser");
        request.addProperty("username", username);
        request.addProperty("password", password);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("keys/client.keystore.pk12"), _keyStorePass);

        final Certificate cert = ks.getCertificate("client");

        request.addProperty("cert", Base64.getEncoder().encodeToString(cert.getEncoded()));

        System.out.println(request.toString());
        os.writeObject(request.toString());

        String line = (String) is.readObject();

        System.out.println("Received:" + line);

        JsonObject replyJson = JsonParser.parseString(line).getAsJsonObject();

        String reply = replyJson.get("response").getAsString().split(":")[0];

        if (reply.equals("OK")) {
            _username = username;
            System.out.println("Result: " + replyJson.get("response").getAsString());
            System.out.println("Register Successful");
        }
        else {
            System.out.println("Result: " + replyJson.get("response").getAsString());
            System.out.println("Register Unsuccessful");
        }
    }


    public void parseCreateFile(Console clientConsole, ObjectOutputStream os, ObjectInputStream is) throws NoSuchAlgorithmException {
        System.out.print("Please enter file path (from the files directory): ");
        String path = clientConsole.readLine().trim();
        System.out.println("Filename: " + path);
        try {
            createFile(path, os, is);
        }catch (InvalidPathException e) {
            System.out.println(e.getMessage());
        } catch (IOException | ClassNotFoundException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException | NoSuchPaddingException | CertificateException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

    }

    /* Types to be better thought out */
    public void createFile(String path, ObjectOutputStream os, ObjectInputStream is) throws NoSuchAlgorithmException, IOException, ClassNotFoundException, InvalidPathException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, CertificateException, KeyStoreException, UnrecoverableKeyException {

        Path filePath = FileSystems.getDefault().getPath(_filesDir, path);
        Path relativeFilePath = FileSystems.getDefault().getPath(_filesDir).relativize(filePath);

        if(relativeFilePath.startsWith("sharedFiles")) {
            throw new InvalidPathException("Can't create a file in the sharedFilesFolder");
        }

        // Generate AES key for the file
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example
        SecretKey secretKey = keyGen.generateKey();

        // Construct JSON request
        JsonObject request = JsonParser.parseString("{}").getAsJsonObject();
        request.addProperty("operation", "CreateFile");
        request.addProperty("username", _username);
        request.addProperty("path", path);


        // Compute signature of file
        FileInputStream fis = new FileInputStream(String.valueOf(filePath));
        request.addProperty("signature", Base64.getEncoder().encodeToString(computeFileSignature(fis)));
        fis.close();

        System.out.println(request.toString());
        os.writeObject(request.toString());

        Cipher fileCipher = getFileCipher(secretKey);

        // Send file 8k bytes at a time
        fis = new FileInputStream(String.valueOf(filePath));
        CipherInputStream cin  = new CipherInputStream(fis, fileCipher);

        byte[] fileChunk = new byte[8*1024];
        int bytesRead;

        while((bytesRead = cin.read(fileChunk)) >= 0) {
            os.writeObject(Arrays.copyOfRange(fileChunk, 0, bytesRead));
            os.flush();
        }
        os.writeObject(Base64.getDecoder().decode("FileDone"));
        os.flush();
        cin.close();

        
        String line;
        System.out.println("Waiting");
        line = (String) is.readObject();

        System.out.println("Received:" + line);

        JsonObject reply = JsonParser.parseString(line).getAsJsonObject();
        System.out.println("Result: " + reply.get("response").getAsString());

    }

    private byte[] computeFileSignature(FileInputStream fis) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Compute checksum of this File and cipher with Private Key
        MessageDigest messageDigest = getMessageDigest();
        byte[] fileChunk = new byte[8*1024];
        int count = 0;
        while ((count = fis.read(fileChunk)) != -1) {
            messageDigest.update(fileChunk, 0, count);
        }

        // Cipher with client's Private Key
        PrivateKey clientPrivateKey = getClientPrivateKey();
        return cipherHash(messageDigest.digest(), clientPrivateKey);
    }

    private MessageDigest getMessageDigest() throws NoSuchAlgorithmException {
        final String DIGEST_ALGO = "SHA-256";
        return MessageDigest.getInstance(DIGEST_ALGO);
    }

    private Cipher getFileCipher(SecretKey symKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, symKey);
       return cipher;
    }

    private byte[] cipherHash(byte[] bytes, PrivateKey clientPrivKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clientPrivKey);
        return cipher.doFinal(bytes);
    }

    public void getFile(String path) {}

    public void writeFile(/*...*/) {}

    public void shareFile(/*...*/) {}

    public void deleteFile(String path) {}

    private void parseExit(ObjectOutputStream os, ObjectInputStream is) throws IOException {
        JsonObject request = JsonParser.parseString("{}").getAsJsonObject();
        request.addProperty("operation", "Exit");

        os.writeObject(request.toString());
        os.close();
        is.close();

    }

    private void connectToServer() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        KeyStore ks = KeyStore.getInstance("PKCS12");

        ks.load(new FileInputStream(_keysDir + "/client.keystore.pk12"), _keyStorePass);
        kmf.init(ks, _keyStorePass);


        KeyStore ksTrust = KeyStore.getInstance("PKCS12");
        ksTrust.load(new FileInputStream(_keysDir + "/client.truststore.pk12"), _keyStorePass);
        TrustManagerFactory tm = TrustManagerFactory.getInstance("SunX509");
        tm.init(ksTrust);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tm.getTrustManagers(), null);

        _currentConnectionSocket = (SSLSocket) sslContext.getSocketFactory().createSocket("localhost", 10000);
        String[] protocols = new String[] {"TLSv1.3"};
        String[] cipherSuites = new String[] {"TLS_AES_128_GCM_SHA256"};

        _currentConnectionSocket.setEnabledProtocols(protocols);
        _currentConnectionSocket.setEnabledCipherSuites(cipherSuites);

        _currentConnectionSocket.startHandshake();
    }

    private PrivateKey getClientPrivateKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(_keysDir + "/client.keystore.pk12"), _keyStorePass);
        return (PrivateKey) ks.getKey("client", _keyStorePass);
    }

    // How to create the socket to communicate with the Server
    /*
    char[] pass = "changeit".toCharArray();

    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    KeyStore ks = KeyStore.getInstance("PKCS12");

        ks.load(new FileInputStream("keys/client.keystore.pk12"), pass);
        kmf.init(ks, pass);


    KeyStore ksTrust = KeyStore.getInstance("PKCS12");
        ksTrust.load(new FileInputStream("keys/client.truststore.pk12"), pass);
    TrustManagerFactory tm = TrustManagerFactory.getInstance("SunX509");
        tm.init(ksTrust);
    SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tm.getTrustManagers(), null);



        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket("localhost", 10000)
        String[] protocols = new String[] {"TLSv1.3"};
        String[] cipherSuites = new String[] {"TLS_AES_128_GCM_SHA256"};

        socket.setEnabledProtocols(protocols);
        socket.setEnabledCipherSuites(cipherSuites);

        socket.startHandshake();
        */



}
