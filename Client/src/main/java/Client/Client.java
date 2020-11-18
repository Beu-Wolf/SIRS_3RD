package Client;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

public class Client {
    public Client() {

    }

    /* Types to be better thought out */
    public void createFile(String path) {}

    public void getFile(String path) {}

    public void writeFile(/*...*/) {}

    public void shareFile(/*...*/) {}

    public void deleteFile(String path) {}

    public void login(/*...*/) {}

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
