package com.springsecuritydemo.ahlaou;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class GeneratorKeyPair {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
        var keyPair=keyPairGenerator.generateKeyPair();//generate keypair
        byte[] pub = keyPair.getPublic().getEncoded();//get public key in byte code
        byte[] pri = keyPair.getPrivate().getEncoded();//get private key in byte code
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream("pub.pem")));
        PemObject pemObject=new PemObject("PUBLIC KEY",pub);// the header of file
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        PemWriter pemWriter2 = new PemWriter(new OutputStreamWriter(new FileOutputStream("pri.pem")));
        PemObject pemObject2=new PemObject("PRIVATE KEY",pri);
        pemWriter2.writeObject(pemObject2);
        pemWriter2.close();
    }
}

