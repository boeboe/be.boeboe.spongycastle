package be.boeboe.spongycastle.jscep;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import org.jscep.client.Client;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.ConsoleCertificateVerifier;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.DistributionPoint;
import org.spongycastle.asn1.x509.DistributionPointName;
import org.spongycastle.asn1.x509.ExtendedKeyUsage;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.GeneralNames;
import org.spongycastle.asn1.x509.KeyPurposeId;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.ContentVerifierProvider;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.PKCSException;

import be.boeboe.spongycastle.chapter6.Utils;


public class JScepClient {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static void main(String[] args) throws Exception {

    KeyPair pair = generateKeyPair();
    
    // The identity of the SCEP client
    X509Certificate clientCertificate = generateClientCertificate(pair);

    // The RSA private key of the SCEP client
    PrivateKey priKey = pair.getPrivate();
    
    // URL used by the SCEP server at example.org
    URL url = new URL("http://127.0.0.1:8080/ejbca/publicweb/apply/scep/pkiclient.exe");
    // URL url = new URL("http://localhost:8443/ejbca/publicweb/apply/scep/noca/pkiclient.exe");
    
    // Construct the client
    Client client = new Client(url, new ConsoleCertificateVerifier());

    // The certification request to send to the SCEP server
    PKCS10CertificationRequest certRequest = generateCertRequest(pair);

    EnrollmentResponse txn = client.enrol(clientCertificate, priKey, certRequest, "AdminCA1");
    
    while (txn.isPending()) {
      Thread.sleep(1000);
      System.out.println("Sleeping 1 sec while SCEP is pending");
    }

    // Retrieve the certificate from the store
    CertStore store = txn.getCertStore();
    X509CertSelector selector = new X509CertSelector();
    Iterator it = store.getCertificates(selector).iterator();
    while (it.hasNext()) {
       System.out.println(((X509Certificate)it.next()).getSubjectX500Principal());
    }
  }

  private static PKCS10CertificationRequest generateCertRequest(KeyPair pair) 
      throws OperatorCreationException, PKCSException {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
    X500Name subject = new X500Name("CN=Boeboe");
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

  private static X509Certificate generateClientCertificate(KeyPair pair) 
      throws CertificateException, NoSuchProviderException, OperatorCreationException, IOException {
    X500Name issuer = new X500Name("CN=Boeboe");
    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
    Date notBefore = new Date(System.currentTimeMillis());
    Date notAfter = new Date(System.currentTimeMillis() + Long.valueOf("788400000000"));
    X500Name subject = new X500Name("CN=Boeboe");;
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());

    // Generate the certificate
    X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
        issuer, serial, notBefore, notAfter, subject, publicKeyInfo);

    // Set certificate extensions
    // (1) digitalSignature extension
    certBuilder.addExtension(X509Extension.keyUsage, true, 
        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));
 
    // (2) extendedKeyUsage extension
    Vector<KeyPurposeId> ekUsages = new Vector<KeyPurposeId>();
    ekUsages.add(KeyPurposeId.id_kp_clientAuth);
    ekUsages.add(KeyPurposeId.id_kp_serverAuth);
    certBuilder.addExtension(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(ekUsages));
    
    // (3) cRLDistributionPoints extension
    GeneralName gn1 = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String("http://www.qeo.org/test.crl", true));
    GeneralNames gns1 = new GeneralNames(gn1);
    DistributionPointName dpn1 = new DistributionPointName(gns1);
    DistributionPoint distp1 = new DistributionPoint(dpn1, null, null);

    GeneralName gn2 = new GeneralName(GeneralName.directoryName, new DERIA5String("CN=CRL1, OU=CloudId, O=Qeo, C=US"));
    GeneralNames gns2 = new GeneralNames(gn2);
    DistributionPointName dpn2 = new DistributionPointName(gns2);
    DistributionPoint distp2 = new DistributionPoint(dpn2, null, null);

    DistributionPoint[] distpArray = {distp1, distp2};
    DERSequence seq = new DERSequence(distpArray);
    certBuilder.addExtension(X509Extension.cRLDistributionPoints,false,seq);
    
    // Sign the certificate
    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA1WithRSAEncryption");
    ContentSigner contentSigner = contentSignerBuilder.build(pair.getPrivate());
    
    X509CertificateHolder holder = certBuilder.build(contentSigner);

    // Retrieve the certificate from holder
    InputStream is1 = new ByteArrayInputStream(holder.getEncoded());
    CertificateFactory cf = CertificateFactory.getInstance("X.509","SC");
    X509Certificate generatedCertificate = (X509Certificate) cf.generateCertificate(is1);
    return generatedCertificate;
  }

  private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    // create the keys
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "SC");
    kpGen.initialize(1024, Utils.createFixedRandom());
    return kpGen.generateKeyPair();
  }
}
