package be.boeboe.spongycastle.chapter8;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import javax.security.auth.x500.X500PrivateCredential;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMWriter;

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
    String[] keyStoreNames = {"BKS", "PKCS12", "UBER", "BouncyCastle"};
    
    for (String keyStoreName : keyStoreNames) {
      KeyStore store = KeyStore.getInstance(keyStoreName, "SC");
      store.load(null, storePassword);

      X500PrivateCredential rootCredential = Utils.createRootCredential();
      System.out.println("?? a ?? " + keyStoreName);
      writePEMtoStdOut(rootCredential.getCertificate(), keyStoreName);
      System.out.println("?? b ?? " + keyStoreName);
      store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());

      File keyStoreFile= new File("/tmp/keystore_" + keyStoreName + ".bks");
      final FileOutputStream fos = new FileOutputStream(keyStoreFile);
      store.store(fos, storePassword);
      fos.close();

      final FileInputStream fis = new FileInputStream(keyStoreFile);
      store.load(fis, storePassword);

      Certificate cert = store.getCertificate(rootCredential.getAlias());
      System.out.println("?? c ?? " + keyStoreName);
      writePEMtoStdOut(cert, keyStoreName);
      System.out.println("?? d ?? " + keyStoreName);
    }
  }
  
  private static void writePEMtoStdOut(Certificate cert, String name) throws IOException {
    File file = new File("/tmp/cert." + name);
    FileWriter fileWriter = new FileWriter(file, true);
    PEMWriter pemWrt = new PEMWriter(fileWriter, "SC");
    pemWrt.writeObject(cert);
    pemWrt.close();
  }

}
