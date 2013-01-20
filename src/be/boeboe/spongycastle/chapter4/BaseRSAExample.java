package be.boeboe.spongycastle.chapter4;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import be.boeboe.spongycastle.chapter4.Utils;

/**
 * Basic RSA example.
 */
public class BaseRSAExample {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static void main(String[] args) throws Exception {
    byte[] input = new byte[] { (byte)0xbe, (byte)0xef };
    Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "SC");

    // create the keys
    KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SC");
    RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
            new BigInteger("11", 16));
    RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
            new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
            new BigInteger("57791d5430d593164082036ad8b29fb1", 16));
    RSAPublicKey pubKey = (RSAPublicKey)keyFactory.generatePublic(pubKeySpec);
    RSAPrivateKey privKey = (RSAPrivateKey)keyFactory.generatePrivate(privKeySpec);
    System.out.println("input : " + Utils.toHex(input));

    // encryption step
    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
    byte[] cipherText = cipher.doFinal(input);
    System.out.println("cipher: " + Utils.toHex(cipherText));

    // decryption step
    cipher.init(Cipher.DECRYPT_MODE, privKey);
    byte[] plainText = cipher.doFinal(cipherText);
    System.out.println("plain : " + Utils.toHex(plainText));
  }
}