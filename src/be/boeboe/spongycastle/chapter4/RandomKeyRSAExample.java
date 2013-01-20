package be.boeboe.spongycastle.chapter4;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import be.boeboe.spongycastle.chapter4.Utils;

/**
 * RSA example with random key generation.
 */
public class RandomKeyRSAExample {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static void main(String[] args) throws Exception {
    byte[] input = new byte[] { (byte)0xbe, (byte)0xef };
    Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "SC");
    SecureRandom random = Utils.createFixedRandom();

    // create the keys
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SC");
    generator.initialize(256, random);
    KeyPair pair = generator.generateKeyPair();
    Key pubKey = pair.getPublic();
    Key privKey = pair.getPrivate();
    System.out.println("input : " + Utils.toHex(input));

    // encryption step
    cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
    byte[] cipherText = cipher.doFinal(input);
    System.out.println("cipher: " + Utils.toHex(cipherText));

    // decryption step
    cipher.init(Cipher.DECRYPT_MODE, privKey);
    byte[] plainText = cipher.doFinal(cipherText);
    System.out.println("plain : " + Utils.toHex(plainText));
  }
}