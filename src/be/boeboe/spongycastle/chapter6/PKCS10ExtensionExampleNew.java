package be.boeboe.spongycastle.chapter6;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Vector;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.ExtendedKeyUsage;
import org.spongycastle.asn1.x509.KeyPurposeId;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.ContentVerifierProvider;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;

/**
 * Generation of a basic PKCS #10 request with an extension.
 */
public class PKCS10ExtensionExampleNew {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static PKCS10CertificationRequest generateRequest(KeyPair pair) throws Exception {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
    X500Name subject = new X500Name("CN=Requested Test Certificate");
    PKCS10CertificationRequestBuilder certificationRequestBuilder = new PKCS10CertificationRequestBuilder(subject, publicKeyInfo);

    certificationRequestBuilder.addAttribute(X509Extension.keyUsage, 
        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));
    
    Vector<KeyPurposeId> ekUsages = new Vector<KeyPurposeId>();
    ekUsages.add(KeyPurposeId.id_kp_clientAuth);
    ekUsages.add(KeyPurposeId.id_kp_serverAuth);
    certificationRequestBuilder.addAttribute(X509Extension.extendedKeyUsage, new ExtendedKeyUsage(ekUsages));

    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA1WithRSAEncryption");
    contentSignerBuilder.setProvider("SC");
    ContentSigner contentSigner = contentSignerBuilder.build(pair.getPrivate());
    
    DERPrintableString password = new DERPrintableString("secret123");
    certificationRequestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);
    
    PKCS10CertificationRequest certificationRequest = certificationRequestBuilder.build(contentSigner);
    
    JcaContentVerifierProviderBuilder contentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
    ContentVerifierProvider contentVerifierProvider = contentVerifierProviderBuilder.build(pair.getPublic());
    System.out.println("isSignatureValid? " + certificationRequest.isSignatureValid(contentVerifierProvider));
    System.out.println(certificationRequest.getSubject());
    return certificationRequest;
  }

  public static void main(String[] args) throws Exception {
    // create the keys
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "SC");
    kpGen.initialize(1024, Utils.createFixedRandom());
    KeyPair pair = kpGen.generateKeyPair();
    PKCS10CertificationRequest request = generateRequest(pair);

    FileOutputStream fstream = new FileOutputStream("/tmp/cert.pem");
    fstream.write(request.getEncoded());
    //Close the output stream
    fstream.close();

    PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
    pemWrt.writeObject(request);
    pemWrt.close();
  }
}