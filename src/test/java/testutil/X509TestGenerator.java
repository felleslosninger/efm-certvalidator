package testutil;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.DateTime;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public abstract  class X509TestGenerator {
    static { Security.addProvider(new BouncyCastleProvider());  }

    protected X509Certificate createX509Certificate(Date from, Date to) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, OperatorCreationException, CertIOException {
        String domainName = "test";
        return createX509Certificate(null, "CN=" + domainName + ", OU=None, O=None L=None, C=None", null, from, to);
    }

    protected X509Certificate createX509Certificate(String subject, X509ExtensionCustom custom, Date from, Date to) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, OperatorCreationException, CertIOException {
        X509Certificate issuer = createX509Certificate();
        return createX509Certificate(issuer, subject, custom, from, to);
    }


    protected X509Certificate createX509Certificate(X509Certificate issuer, String subject, X509ExtensionCustom custom, Date from, Date to) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, OperatorCreationException, CertIOException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048, random);
        KeyPair keyPair = kpGen.generateKeyPair();
        PublicKey RSAPubKey = keyPair.getPublic();
        PrivateKey RSAPrivateKey = keyPair.getPrivate();

        X500Name issuerName = null;
        if(issuer != null)
            issuerName = new X500Name(issuer.getSubjectX500Principal().getName());
        else
            issuerName = new X500Name("CN=" + "test" + ", OU=None, O=None L=None, C=None");

        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(RSAPubKey.getEncoded()));


        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
                issuerName,
                BigInteger.valueOf(Math.abs(new SecureRandom().nextInt())),
                from,
                to,
                new X500Name(subject),
                subjPubKeyInfo
            );

        if(custom != null)
            custom.setup(v3CertGen);


        //Content Signer
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(RSAPrivateKey);


        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(sigGen));
    }

    protected X509Certificate createX509Certificate(X509ExtensionCustom x509ExtensionCustom) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, OperatorCreationException, CertIOException {
        String domainName = "test";
        return createX509Certificate("CN=" + domainName + ", OU=None, O=None L=None, C=None", x509ExtensionCustom, DateTime.now().minusYears(1).toDate(), DateTime.now().plusYears(1).toDate());
    }

    protected X509Certificate createX509Certificate() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, OperatorCreationException, CertIOException {
        return createX509Certificate(DateTime.now().minusYears(1).toDate(), DateTime.now().plusYears(1).toDate());
    }

    protected X509Certificate createX509Certificate(String s) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, OperatorCreationException, CertIOException {
        return createX509Certificate(s, null, DateTime.now().minusYears(1).toDate(), DateTime.now().plusYears(1).toDate());
    }


    protected X509Certificate constructCertWithCertificatePolicie(final String policie) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        return createX509Certificate(new X509ExtensionCustom() {
                @Override
                public void setup(X509v3CertificateBuilder v3CertGen) throws CertIOException {

                    v3CertGen.addExtension(Extension.certificatePolicies, true, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(policie))));

                }
            });
    }
}
