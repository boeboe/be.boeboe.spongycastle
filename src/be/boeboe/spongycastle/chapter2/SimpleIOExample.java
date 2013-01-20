package be.boeboe.spongycastle.chapter2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * Basic IO example with CTR using AES
 */
public class SimpleIOExample {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  @SuppressWarnings("resource")
  public static void main(String[] args) throws Exception {
    byte[] input = new byte[] {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    byte[] keyBytes = new byte[] {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    byte[] ivBytes = new byte[] {
                        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "SC");
    System.out.println("input : " + Utils.toHex(input));

    // encryption pass
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    ByteArrayInputStream bIn = new ByteArrayInputStream(input);
    CipherInputStream cIn = new CipherInputStream(bIn, cipher);
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    int ch;
    while ((ch = cIn.read()) >= 0) { bOut.write(ch); }
    byte[] cipherText = bOut.toByteArray();
    System.out.println("cipher: " + Utils.toHex(cipherText));

    // decryption pass
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    bOut = new ByteArrayOutputStream();
    CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
    cOut.write(cipherText);
    cOut.close();
    System.out.println("plain: " + Utils.toHex(bOut.toByteArray()));
  }
}