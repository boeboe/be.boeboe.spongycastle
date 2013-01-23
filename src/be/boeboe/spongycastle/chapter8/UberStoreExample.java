package be.boeboe.spongycastle.chapter8;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import javax.security.auth.x500.X500PrivateCredential;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMWriter;

import be.boeboe.spongycastle.chapter8.Utils;

/**
 * Example of basic use of KeyStore.
 */
public class UberStoreExample {
  public static char[] keyPassword = "key".toCharArray();
  public static char[] storePassword = "store".toCharArray();

  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static void main(String[] args) throws Exception {
//    KeyStore storePKCS12 = KeyStore.getInstance("PKCS12", "SC");
//    storePKCS12.load(null, null);
//    storePKCS12.store(new FileOutputStream("/tmp/keystore.pkcs12"), storePassword);

    KeyStore storeBKS = KeyStore.getInstance("BKS", "SC");
    storeBKS.load(null, null);
    
    X500PrivateCredential rootCredential = Utils.createRootCredential();
    System.out.println("?? a ??");
    writePEMtoStdOut(rootCredential.getCertificate());
    System.out.println("?? b ??");
    storeBKS.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
    
    File keyStoreFile= new File("/tmp/keystore.bks");
    final FileOutputStream fos = new FileOutputStream(keyStoreFile);
    storeBKS.store(fos, storePassword);
    fos.close();
    
    final FileInputStream fis = new FileInputStream(keyStoreFile);
    storeBKS.load(fis, storePassword);
    
    Certificate cert = storeBKS.getCertificate(rootCredential.getAlias());
    System.out.println("?? c ??");
    writePEMtoStdOut(cert);
    System.out.println("?? d ??");
    
//    KeyStore storeUBER = KeyStore.getInstance("UBER", "SC");
//    storeUBER.load(null, null);
//    storeUBER.store(new FileOutputStream("/tmp/keystore.uber"), storePassword);
  }
  
  private static void writePEMtoStdOut(Certificate cert) throws IOException {
    File file = new File("/tmp/cert.debug");
    FileWriter fileWriter = new FileWriter(file, true);
    PEMWriter pemWrt = new PEMWriter(fileWriter, "SC");
    pemWrt.writeObject(cert);
    pemWrt.close();
  }

}
