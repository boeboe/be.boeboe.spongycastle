package be.boeboe.spongycastle.chapter6;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMWriter;

/**
 * Basic example of using a CertificateFactory.
 */
public class CertificateFactoryExample {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static void main(String[] args) throws Exception {
    // create the keys
    KeyPair pair = Utils.generateRSAKeyPair();;

    // create the input stream
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    File file = new File("/tmp/cert.pem");
    FileWriter fileWriter = new FileWriter(file);
    PEMWriter pemWrt = new PEMWriter(fileWriter, "SC");
    pemWrt.writeObject(X509V3CreateExampleNew.generateV3Certificate(pair));
    pemWrt.close();
    System.out.println(Utils.toString(bOut.toByteArray()));

    bOut.write(X509V3CreateExampleNew.generateV3Certificate(pair).getEncoded());
    bOut.close();
    InputStream in = new ByteArrayInputStream(bOut.toByteArray());

    // create the certificate factory
    CertificateFactory fact = CertificateFactory.getInstance("X.509","SC");

    // read the certificate
    X509Certificate x509Cert = (X509Certificate)fact.generateCertificate(in);
    System.out.println("issuer: " + x509Cert.getIssuerX500Principal());
  }
}
