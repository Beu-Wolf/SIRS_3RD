package sirs.server;

import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.TreeMap;

public class MainServer {

    private TreeMap<String, ClientInfo> _clients = new TreeMap<>();
    private ArrayList<FileInfo> _files = new ArrayList<>();



    private String _host;
    private int _port;
    private char[] _password;

    public MainServer(String host, int port) {
        _host = host;
        _port = port;
        _password = "changeit".toCharArray();

    }

    public void handleComms(SSLSocket s) {
        System.out.println("accepted");
        try {
            InputStream is = new BufferedInputStream(s.getInputStream());
            OutputStream os = new BufferedOutputStream(s.getOutputStream());
            byte[] data = new byte[2048];
            int len = is.read(data);
            if (len <= 0) {
                throw new IOException("no data received");
            }
            System.out.printf("server received %d bytes: %s%n",
                    len, new String(data, 0, len));
            os.write(data, 0, len);
            os.flush();
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
                handleComms(s);

            }
        } catch (IOException e) {
            e.printStackTrace();
        }


    }



    public void receiveUserKey(String url, PublicKey publicKey, String username) { // Can also receive the message here and parse in this function
        _clients.put(username, new ClientInfo(url, publicKey, username));
    }

    public void createNewFile(String path, ClientInfo owner, SecretKeySpec fileKey, String initialContent) {
        File file = new File(path);
        _files.add(new FileInfo(file, owner, fileKey));

        try (FileWriter fw = new FileWriter(file)) {
            fw.write(initialContent);
        } catch (IOException e) {
            e.printStackTrace();
        }
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

}
