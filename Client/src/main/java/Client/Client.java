package Client;

import Client.exceptions.InvalidPathException;
import Client.exceptions.RecoverException;
import Client.exceptions.InvalidUsernameException;
import Client.exceptions.MessageNotAckedException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.*;
import javax.net.ssl.*;
import java.io.*;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.regex.Pattern;

public class Client {

    private String _username;
    private String _serverHost;
    private int _serverPort;
    private String _filesDir;
    private String _keysDir;
    SSLSocket _currentConnectionSocket;
    private char[] _keyStorePass = "changeit".toCharArray();
    private HashMap<Path, FileInfo> _files = new HashMap<>();


    public Client(String serverHost, int serverPort, String filesDir, String keysDir) {
        _serverHost = serverHost;
        _serverPort = serverPort;
        _filesDir = filesDir;
        _keysDir = keysDir;
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
                    } else if (Pattern.matches("^register$", command)) {
                        parseRegister(scanner, os, is);
                    } else if (Pattern.matches("^login$", command)) {
                        parseLogin(scanner, os, is);
                    } else if(Pattern.matches("^create file$", command)) {
                        parseCreateFile(scanner, os, is);
                    } else if(Pattern.matches("^edit file$", command)) {
                        parseEditFile(scanner, os, is);
                    } else if(Pattern.matches("^recover file$", command)) {
                        parseRecoverFile(scanner, os, is);
                    }


            }
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | KeyManagementException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        scanner.close();

    }
    public void parseLogin(Scanner scanner, ObjectOutputStream os, ObjectInputStream is) throws IOException, ClassNotFoundException {

        System.out.println("Please enter your username");
        String username = scanner.nextLine().trim();
        _username = username;
        System.out.println("Please enter your password");
        String password = scanner.nextLine().trim();

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

    public void parseRegister(Scanner scanner, ObjectOutputStream os, ObjectInputStream is) throws IOException, KeyStoreException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException {
        System.out.println("Please enter your username");
        String username = scanner.nextLine().trim();
        System.out.println("Please enter your password");
        String pw1 = scanner.nextLine().trim();
        System.out.println("Please re-enter your password to confirm");
        String pw2 = scanner.nextLine().trim();
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


    public void parseCreateFile(Scanner scanner, ObjectOutputStream os, ObjectInputStream is) throws NoSuchAlgorithmException {
        System.out.print("Please enter file path (from the " + _filesDir + " directory): ");
        String path = scanner.nextLine().trim();
        System.out.println("Filename: " + path);
        try {
            createFile(path, os, is);
        }catch (InvalidPathException | MessageNotAckedException | InvalidUsernameException e) {
            System.out.println(e.getMessage());
        } catch (IOException | ClassNotFoundException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException | NoSuchPaddingException | CertificateException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

    }

    /* Types to be better thought out */
    public void createFile(String path, ObjectOutputStream os, ObjectInputStream is) throws NoSuchAlgorithmException, IOException, ClassNotFoundException, InvalidPathException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, CertificateException, KeyStoreException, UnrecoverableKeyException, MessageNotAckedException, InvalidUsernameException {

        if(_username == null) {
            throw new InvalidUsernameException("Not registered or logged in yet!");
        }

        Path filePath = FileSystems.getDefault().getPath(_filesDir, path);
        Path relativeFilePath = FileSystems.getDefault().getPath(_filesDir).relativize(filePath);

        if(relativeFilePath.startsWith("sharedFiles")) {
            throw new InvalidPathException("Can't create a file in the sharedFilesFolder");
        }

        // Generate AES key for the file
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example
        SecretKey secretKey = keyGen.generateKey();

        _files.put(relativeFilePath, new FileInfo(_username, new File(String.valueOf(filePath)), secretKey));

        // Construct JSON request
        JsonObject request = JsonParser.parseString("{}").getAsJsonObject();
        request.addProperty("operation", "CreateFile");
        request.addProperty("username", _username);
        request.addProperty("path", relativeFilePath.toString());

        System.out.println(request.toString());
        os.writeObject(request.toString());

        // Wait for ACK
        ackMessage(is);

        byte[] fileSignature = sendFileToServer(os, filePath, secretKey);

        ackMessage(is);

        request = JsonParser.parseString("{}").getAsJsonObject();
        request.addProperty("signature", Base64.getEncoder().encodeToString(fileSignature));

        System.out.println(request.toString());
        os.writeObject(request.toString());

        ackMessage(is);
        System.out.println("Operation Successful");
    }



    public void parseEditFile(Scanner scanner, ObjectOutputStream os, ObjectInputStream is) {
        System.out.print("Please enter file path to edit (from the files directory): ");
        String path = scanner.nextLine().trim();
        System.out.println("Filename: " + path);

        try {
            editFile(path, os, is);
        } catch (InvalidKeyException | KeyStoreException | CertificateException | NoSuchAlgorithmException | InvalidPathException | IOException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | UnrecoverableKeyException | ClassNotFoundException | MessageNotAckedException | InvalidUsernameException e) {
            e.printStackTrace();
        }
    }

    public void editFile(String path, ObjectOutputStream os, ObjectInputStream is) throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, InvalidPathException, ClassNotFoundException, MessageNotAckedException, InvalidUsernameException {
        if(_username == null) {
            throw new InvalidUsernameException("Not registered or logged in yet!");
        }

        Path filePath = FileSystems.getDefault().getPath(_filesDir, path);
        Path relativeFilePath = FileSystems.getDefault().getPath(_filesDir).relativize(filePath);

        if(!_files.containsKey(relativeFilePath)) {
            throw new InvalidPathException("File does not exist");
        }

        SecretKey fileSecretKey = _files.get(relativeFilePath).getFileSymKey();

        JsonObject request = JsonParser.parseString("{}").getAsJsonObject();
        request.addProperty("operation", "EditFile");
        request.addProperty("username", _username);


        // Remove the sharedFiles directory for path (server does not care about it)
        if(relativeFilePath.startsWith("sharedFiles")) {
            relativeFilePath = relativeFilePath.subpath(1, relativeFilePath.getNameCount());
            request.addProperty("ownerEdit", false);
        } else {
            request.addProperty("ownerEdit", true);
        }
        request.addProperty("path", relativeFilePath.toString());

        System.out.println(request.toString());
        os.writeObject(request.toString());

        ackMessage(is);

        byte[] newFileSignature = sendFileToServer(os, filePath, fileSecretKey);

        ackMessage(is);

        request = JsonParser.parseString("{}").getAsJsonObject();
        request.addProperty("signature", Base64.getEncoder().encodeToString(newFileSignature));

        System.out.println(request.toString());
        os.writeObject(request.toString());

        ackMessage(is);
        System.out.println("Operation Successful");
    }

    // Sends file to server and returns the created signature
    private byte[] sendFileToServer(ObjectOutputStream os, Path filePath, SecretKey fileSecretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        FileInputStream fis;
        Cipher fileCipher = getFileCipher(fileSecretKey, Cipher.ENCRYPT_MODE);
        MessageDigest messageDigest = getMessageDigest();

        // Send file 8k bytes at a time
        fis = new FileInputStream(String.valueOf(filePath));
        try (CipherInputStream cin = new CipherInputStream(fis, fileCipher)) {

            byte[] fileChunk = new byte[8 * 1024];
            int bytesRead;

            while ((bytesRead = cin.read(fileChunk)) >= 0) {
                messageDigest.update(fileChunk, 0, bytesRead);
                os.writeObject(Arrays.copyOfRange(fileChunk, 0, bytesRead));
                os.flush();
            }
            os.writeObject(Base64.getDecoder().decode("FileDone"));
            os.flush();
        }

        // returns signature of sent file
        // Compute checksum of this File and cipher with Private Key
        PrivateKey clientPrivateKey = getClientPrivateKey();
        return cipherHash(messageDigest.digest(), clientPrivateKey);
    }

    private void parseRecoverFile(Scanner scanner, ObjectOutputStream os, ObjectInputStream is) {
        System.out.print("Please enter file path to recover (from the files directory): ");
        String path = scanner.nextLine().trim();
        System.out.println("Filename: " + path);
        try {
            recoverFile(path, os, is);
        } catch (InvalidPathException | IOException | ClassNotFoundException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException | RecoverException e) {
            e.printStackTrace();
        }
    }

    private void recoverFile(String path, ObjectOutputStream os, ObjectInputStream is) throws InvalidPathException, IOException, ClassNotFoundException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, RecoverException {
        Path filePath = FileSystems.getDefault().getPath("files", path);
        Path relativeFilePath = FileSystems.getDefault().getPath("files").relativize(filePath);

        if(!_files.containsKey(relativeFilePath)) {
            throw new InvalidPathException("File does not exist");
        }

        JsonObject request = JsonParser.parseString("{}").getAsJsonObject();
        request.addProperty("operation", "RecoverFile");
        request.addProperty("username", _username);

        if(relativeFilePath.startsWith("sharedFiles")) {
            relativeFilePath = relativeFilePath.subpath(1, relativeFilePath.getNameCount());
            request.addProperty("ownedFile", false);
        } else {
            request.addProperty("ownedFile", true);
        }

        request.addProperty("path", relativeFilePath.toString());

        System.out.println(request.toString());
        os.writeObject(request.toString());

        String line;
        System.out.println("Waiting");
        line = (String) is.readObject();

        JsonObject serverResponse = JsonParser.parseString(line).getAsJsonObject();
        System.out.println("Response: " + serverResponse.get("response").getAsString());

        if (!serverResponse.get("response").getAsString().equals("SendingFile")) {
            // someting went wrong
            throw new RecoverException("Could not recover file");
        }


        // Clean File
        new FileOutputStream(_files.get(relativeFilePath).getFile()).close();
        // Read file from socket
        receiveFileFromSocket(_files.get(relativeFilePath).getFile(), _files.get(relativeFilePath).getFileSymKey(), is);

        line = (String) is.readObject();

        System.out.println("Received:" + line);

        JsonObject reply = JsonParser.parseString(line).getAsJsonObject();
        System.out.println("Result: " + reply.get("response").getAsString());

    }

    private void receiveFileFromSocket(File file, SecretKey sk, ObjectInputStream is) throws IOException, ClassNotFoundException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] fileChunk;
        boolean fileFinish = false;

        Cipher fileCipher = getFileCipher(sk, Cipher.DECRYPT_MODE);

        FileOutputStream fos = new FileOutputStream(file);
        CipherOutputStream con = new CipherOutputStream(fos, fileCipher);

        while(!fileFinish) {
            fileChunk = (byte[]) is.readObject();
            if (Base64.getEncoder().encodeToString(fileChunk).equals("FileDone")) {
                fileFinish = true;
            } else {
                con.write(fileChunk);
            }
        }
        con.close();
    }

    private MessageDigest getMessageDigest() throws NoSuchAlgorithmException {
        final String DIGEST_ALGO = "SHA-256";
        return MessageDigest.getInstance(DIGEST_ALGO);
    }

    private Cipher getFileCipher(SecretKey symKey, int opmode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(opmode, symKey);
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
