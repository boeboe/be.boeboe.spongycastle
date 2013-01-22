package be.boeboe.spongycastle.chapter6;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * Chapter 6 Utils
 */
public class Utils extends be.boeboe.spongycastle.chapter4.Utils {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  /**
  * Create a random 1024 bit RSA key pair
  */
  public static KeyPair generateRSAKeyPair() throws Exception {
   KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "SC");
   kpGen.initialize(1024, new SecureRandom());
   return kpGen.generateKeyPair();
  }
}
