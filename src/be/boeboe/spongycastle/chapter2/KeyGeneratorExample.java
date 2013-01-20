package be.boeboe.spongycastle.chapter2;

import java.security.Key;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * Basic example using the KeyGenerator class and
 * showing how to create a SecretKeySpec from an encoded key.
 */
public class KeyGeneratorExample {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static void main(String[] args) throws Exception {
    byte[] input = new byte[] {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    byte[] ivBytes = new byte[] {
                        0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "SC");
    KeyGenerator generator = KeyGenerator.getInstance("AES", "SC");
    generator.init(192);
    Key encryptionKey = generator.generateKey();
    System.out.println("encryption key : " + Utils.toHex(encryptionKey.getEncoded()));
    System.out.println("input : " + Utils.toHex(input));

    // encryption pass
    cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
    byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
    int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
    ctLength += cipher.doFinal(cipherText, ctLength);

    // create our decryption key using information
    // extracted from the encryption key
    Key decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());
    System.out.println("decryption key : " + Utils.toHex(decryptionKey.getEncoded()));
    cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
    byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
    int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
    ptLength += cipher.doFinal(plainText, ptLength);
    System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
  }
}