package be.boeboe.spongycastle.chapter1;

import java.security.Security;
import javax.crypto.Cipher;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * Basic demonstration of precedence in action.
 */
public class PrecedenceTest {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static void main(String[] args) throws Exception {
    Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
    System.out.println(cipher.getProvider());
    cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "SC");
    System.out.println(cipher.getProvider());
  }
}
