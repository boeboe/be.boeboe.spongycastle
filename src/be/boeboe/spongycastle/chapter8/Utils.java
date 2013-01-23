package be.boeboe.spongycastle.chapter8;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500PrivateCredential;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * Chapter 8 Utils
 */
public class Utils extends be.boeboe.spongycastle.chapter7.Utils {
  public static String ROOT_ALIAS = "root";
  public static String INTERMEDIATE_ALIAS = "intermediate";
  public static String END_ENTITY_ALIAS = "end";

  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  /**
   * Generate a X500PrivateCredential for the root entity.
   */
  public static X500PrivateCredential createRootCredential() throws Exception {
    KeyPair rootPair = generateRSAKeyPair();
    X509Certificate rootCert = generateRootCert(rootPair);
    return new X500PrivateCredential(rootCert, rootPair.getPrivate(), ROOT_ALIAS);
  }

  /**
   * Generate a X500PrivateCredential for the intermediate entity.
   */
  public static X500PrivateCredential createIntermediateCredential(PrivateKey caKey, X509Certificate caCert) throws Exception {
    KeyPair interPair = generateRSAKeyPair();
    X509Certificate interCert = generateIntermediateCert(interPair.getPublic(), caKey, caCert);
    return new X500PrivateCredential(interCert, interPair.getPrivate(), INTERMEDIATE_ALIAS);
  }

  /**
   * Generate a X500PrivateCredential for the end entity.
   */
  public static X500PrivateCredential createEndEntityCredential(PrivateKey caKey, X509Certificate caCert) throws Exception {
    KeyPair endPair = generateRSAKeyPair();
    X509Certificate endCert = generateEndEntityCert(endPair.getPublic(), caKey, caCert);
    return new X500PrivateCredential(endCert, endPair.getPrivate(), END_ENTITY_ALIAS);
  }
}
