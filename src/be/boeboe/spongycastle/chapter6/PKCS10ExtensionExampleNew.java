package be.boeboe.spongycastle.chapter6;

import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Vector;

import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.BasicConstraints;
import org.spongycastle.asn1.x509.ExtendedKeyUsage;
import org.spongycastle.asn1.x509.ExtensionsGenerator;
import org.spongycastle.asn1.x509.KeyPurposeId;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.util.PrivateKeyFactory;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.ContentVerifierProvider;
import org.spongycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.bc.BcRSAContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * Generation of a basic PKCS #10 request with an extension.
 */
public class PKCS10ExtensionExampleNew {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static PKCS10CertificationRequest generateRequest(KeyPair pair) throws Exception {
    
    
    URI uri = new URI("https", "test.test.com", "/cgi-bin/pkiclient.exe", null);
    URL server = uri.toURL();

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

    keyGen.initialize(1048, new SecureRandom());
    KeyPair keypair = keyGen.generateKeyPair();

    String principal = "CN=aTest, OU=TestOU, O=Fidelity, C=US";

    AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(keypair.getPrivate().getEncoded());

    AlgorithmIdentifier signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder()
    .find("SHA1WITHRSA");

    AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find("SHA-1");

    ContentSigner signer = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(privateKey);

    PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(
    principal), keypair.getPublic());

    ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

    extensionsGenerator.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(true));

    extensionsGenerator.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign
    | KeyUsage.cRLSign));

    csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

    PKCS10CertificationRequest csr = csrBuilder.build(signer);

    return csr;
    
//    X500Name subject = new X500Name("CN=Requested Test Certificate");
//    PKCS10CertificationRequestBuilder certificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic());
//
//    ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
//    extensionsGenerator.addExtension(X509Extension.keyUsage, true, new KeyUsage(
//        KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));
//    
//    Vector<KeyPurposeId> ekUsages = new Vector<KeyPurposeId>();
//    ekUsages.add(KeyPurposeId.id_kp_clientAuth);
//    ekUsages.add(KeyPurposeId.id_kp_serverAuth);
//    extensionsGenerator.addExtension(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(ekUsages));
//    certificationRequestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
//
//    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA1WithRSAEncryption");
//    contentSignerBuilder.setProvider("SC");
//    ContentSigner contentSigner = contentSignerBuilder.build(pair.getPrivate());
//    
//    DERPrintableString password = new DERPrintableString("secret123");
//    certificationRequestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);
//    
//    PKCS10CertificationRequest certificationRequest = certificationRequestBuilder.build(contentSigner);
//    
//    JcaContentVerifierProviderBuilder contentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
//    ContentVerifierProvider contentVerifierProvider = contentVerifierProviderBuilder.build(pair.getPublic());
//    System.out.println("isSignatureValid? " + certificationRequest.isSignatureValid(contentVerifierProvider));
//    System.out.println(certificationRequest.getSubject());
//    return certificationRequest;
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