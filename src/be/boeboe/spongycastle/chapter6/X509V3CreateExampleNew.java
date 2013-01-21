package be.boeboe.spongycastle.chapter6;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERSequence;
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
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Basic X.509 V3 Certificate creation with TLS flagging.
 */
public class X509V3CreateExampleNew {
  static {
    BouncyCastleProvider prov = new org.spongycastle.jce.provider.BouncyCastleProvider();
    Security.addProvider(prov);
  }

  public static X509Certificate generateV3Certificate(KeyPair pair)
    throws InvalidKeyException, NoSuchProviderException, SignatureException, OperatorCreationException, IOException, CertificateException {

    X500Name issuer = new X500Name("CN=Qeo Self Signed Cert");
    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
    Date notBefore = new Date(System.currentTimeMillis());
    Date notAfter = new Date(System.currentTimeMillis() + Long.valueOf("788400000000"));
    X500Name subject = new X500Name("CN=Qeo Self Signed Cert");;
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

  public static void main(String[] args) throws Exception {
    // Create the keys
    KeyPair pair = Utils.generateRSAKeyPair();

    // generate the certificate
    X509Certificate cert = generateV3Certificate(pair);

    // show some basic validation
    cert.checkValidity(new Date());
    cert.verify(cert.getPublicKey());
    System.out.println("valid certificate generated");
  }
}