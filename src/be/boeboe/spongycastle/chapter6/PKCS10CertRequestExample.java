package be.boeboe.spongycastle.chapter6;

import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.jce.PKCS10CertificationRequest;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMWriter;

/**
 * Generation of a basic PKCS #10 request.
 */
public class PKCS10CertRequestExample {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static PKCS10CertificationRequest generateRequest(KeyPair pair) throws Exception {
    return new PKCS10CertificationRequest("SHA256withRSA",
          new X500Principal("CN=Requested Test Certificate"),
          pair.getPublic(),
          null,
          pair.getPrivate());
  }

  public static void main(String[] args) throws Exception {
    // create the keys
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "SC");
    kpGen.initialize(1024, Utils.createFixedRandom());
    KeyPair pair = kpGen.generateKeyPair();
    PKCS10CertificationRequest request = generateRequest(pair);
    PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
    pemWrt.writeObject(request);
    pemWrt.close();
  }
}
