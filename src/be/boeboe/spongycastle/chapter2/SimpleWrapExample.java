package be.boeboe.spongycastle.chapter2;

import java.security.Key;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class SimpleWrapExample {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static void main(String[] args) throws Exception {
    // create a key to wrap
    KeyGenerator generator = KeyGenerator.getInstance("AES", "SC");
    generator.init(128);
    Key keyToBeWrapped = generator.generateKey();
    System.out.println("input    : " + Utils.toHex(keyToBeWrapped.getEncoded()));

    // create a wrapper and do the wrapping
    Cipher cipher = Cipher.getInstance("AESWrap", "SC");
    KeyGenerator keyGen = KeyGenerator.getInstance("AES", "SC");
    keyGen.init(256);
    Key wrapKey = keyGen.generateKey();
    cipher.init(Cipher.WRAP_MODE, wrapKey);
    byte[] wrappedKey = cipher.wrap(keyToBeWrapped);
    System.out.println("wrapped : " + Utils.toHex(wrappedKey));

    // unwrap the wrapped key
    cipher.init(Cipher.UNWRAP_MODE, wrapKey);
    Key key = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    System.out.println("unwrapped: " + Utils.toHex(key.getEncoded()));
  }
}