package be.boeboe.spongycastle.chapter6;

import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Vector;
import javax.security.auth.x500.X500Principal;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.pkcs.Attribute;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.GeneralNames;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.asn1.x509.X509Extensions;
import org.spongycastle.jce.PKCS10CertificationRequest;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * Generation of a basic PKCS #10 request with an extension.
 */
public class PKCS10ExtensionExample {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static PKCS10CertificationRequest generateRequest( KeyPair pair) throws Exception {
    // create a SubjectAlternativeName extension value
    GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test"));

    // create the extensions object and add it as an attribute
    Vector oids = new Vector();
    Vector values = new Vector();
    oids.add(X509Extensions.SubjectAlternativeName);
    values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
    X509Extensions extensions = new X509Extensions(oids, values);
    Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));

    return new PKCS10CertificationRequest(
           "SHA256withRSA",
           new X500Principal("CN=Requested Test Certificate"),
           pair.getPublic(),
           new DERSet(attribute),
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