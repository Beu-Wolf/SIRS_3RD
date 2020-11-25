package Client;

import Client.exceptions.InvalidPathException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.internal.bind.DateTypeAdapter;

import javax.crypto.*;
import javax.net.ssl.*;
import java.io.*;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class Client {

    private String _username = "testUser"; // change this to be defined when registering/logging in
    private String _serverHost;
    private int _serverPort;
    SSLSocket _currentConnectionSocket;
    private char[] _keyStorePass = "changeit".toCharArray();

    public Client(String serverHost, int serverPort) {
        _serverHost = serverHost;
        _serverPort = serverPort;
    }

    public void interactive() {
        Scanner scanner = new Scanner(System.in);
        try {
            connectToServer();
            ObjectOutputStream os = new ObjectOutputStream(_currentConnectionSocket.getOutputStream());
            ObjectInputStream is = new ObjectInputStream(_currentConnectionSocket.getInputStream());
            while(true) {
                System.out.print("> ");

                    String command = scanner.nextLine().trim();
                    if (Pattern.matches("^exit$", command)) {
                        parseExit(os, is);
                        if(_currentConnectionSocket != null) {
                            _currentConnectionSocket.close();
                        }
                        break;
                    } else if(Pattern.matches("^create file$", command)) {
                        parseCreateFile(scanner, os, is);
                    }


            }
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | KeyManagementException e) {
            e.printStackTrace();
        }
        scanner.close();

    }


    public void parseCreateFile(Scanner scanner, ObjectOutputStream os, ObjectInputStream is) throws NoSuchAlgorithmException {
        System.out.print("Please enter file path (from the files directory): ");
        String path = scanner.nextLine().trim();
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

        Path filePath = FileSystems.getDefault().getPath("files", path);

        if(Arrays.asList(StreamSupport.stream(filePath.spliterator(), false).map(Path::toString).toArray(String[]::new)).contains("sharedFiles")) {
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

        byte[] fileBytes = Files.readAllBytes(filePath);

        request.addProperty("file_checksum", Base64.getEncoder().encodeToString(computeFileChecksum(fileBytes)));

        // Encrypt with generated key
        byte[] cipheredFile = cipherFile(fileBytes, secretKey);

        // TODO: Change this to send file in little chunks
        request.addProperty("filesize", cipheredFile.length);

        System.out.println(request.toString());
        os.writeObject(request.toString());

        // Send file 8k bytes at a time
        int chunk = 8*1024;
        int fileStart = 0;
        while(fileStart < cipheredFile.length) {
            int end = Math.min(cipheredFile.length, fileStart + chunk);
            os.write(Arrays.copyOfRange(cipheredFile, fileStart, end));
            os.flush();
            fileStart += chunk;
        }

        String line;
        System.out.println("Waiting");
        line = (String) is.readObject();

        System.out.println("Received:" + line);

        JsonObject reply = JsonParser.parseString(line).getAsJsonObject();
        System.out.println("Result: " + reply.get("response").getAsString());

    }

    private byte[] computeFileChecksum(byte[] fileBytes) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Compute checksum of this File and cipher with Public Key
        byte[] checksum = HashBytes(fileBytes);

        // Cipher with client's Public Key
        PrivateKey clientPrivateKey = getClientPrivateKey();
        return cipherHash(checksum, clientPrivateKey);
    }

    private byte[] HashBytes(byte[] cipheredBytes) throws NoSuchAlgorithmException {
        final String DIGEST_ALGO = "SHA-256";
        MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);
        messageDigest.update(cipheredBytes);
        return messageDigest.digest();
    }

    private byte[] cipherFile(byte[] fileBytes, SecretKey symKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, symKey);
       return cipher.doFinal(fileBytes);
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

    public void login(/*...*/) {}

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

        ks.load(new FileInputStream("keys/client.keystore.pk12"), _keyStorePass);
        kmf.init(ks, _keyStorePass);


        KeyStore ksTrust = KeyStore.getInstance("PKCS12");
        ksTrust.load(new FileInputStream("keys/client.truststore.pk12"), _keyStorePass);
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
        ks.load(new FileInputStream("keys/client.keystore.pk12"), _keyStorePass);
        return (PrivateKey) ks.getKey("localhost", _keyStorePass);
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
