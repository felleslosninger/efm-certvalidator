package no.difi.virksomhetssertifikat.usage;

import no.difi.virksomhetssertifikat.*;
import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.util.KeystoreCertificateBucket;
import no.difi.virksomhetssertifikat.util.SimplePrincipalNameProvider;
import org.junit.Test;

public class PeppolTest {

    @Test
    public void simpleTestAp() throws Exception {
        KeystoreCertificateBucket keystoreCertificateBucket = new KeystoreCertificateBucket("JKS", getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        CertificateBucket rootCertificates = keystoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keystoreCertificateBucket.toSimple("peppol-ap");

        ValidatorBuilder.newInstance()
                .append(new ExpirationValidator())
                .append(new PrincipalNameValidator("CN", new SimplePrincipalNameProvider("PEPPOL ACCESS POINT TEST CA"), PrincipalNameValidator.Principal.ISSUER))
                .append(new Chain2Validator(rootCertificates, intermediateCertificates))
                // .append(new OCSPValidator(intermediateCertificates))
                .append(new CRLValidator())
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }

    @Test
    public void simpleTestSmp() throws Exception {
        KeystoreCertificateBucket keystoreCertificateBucket = new KeystoreCertificateBucket("JKS", getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        CertificateBucket rootCertificates = keystoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keystoreCertificateBucket.toSimple("peppol-ap");

        ValidatorBuilder.newInstance()
                .append(new ExpirationValidator())
                .append(new PrincipalNameValidator("CN", new SimplePrincipalNameProvider("PEPPOL SERVICE METADATA PUBLISHER TEST CA"), PrincipalNameValidator.Principal.ISSUER))
                .append(new Chain2Validator(rootCertificates, intermediateCertificates))
                // .append(new OCSPValidator(intermediateCertificates))
                .append(new CRLValidator())
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer"));
    }

    @Test
    public void simpleProdAp() throws Exception {
        KeystoreCertificateBucket keystoreCertificateBucket = new KeystoreCertificateBucket("JKS", getClass().getResourceAsStream("/peppol-prod.jks"), "peppol");
        CertificateBucket rootCertificates = keystoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keystoreCertificateBucket.toSimple("peppol-ap");

        ValidatorBuilder.newInstance()
                .append(new ExpirationValidator())
                .append(new PrincipalNameValidator("CN", new SimplePrincipalNameProvider("PEPPOL ACCESS POINT CA"), PrincipalNameValidator.Principal.ISSUER))
                .append(new Chain2Validator(rootCertificates, intermediateCertificates))
                // .append(new OCSPValidator(intermediateCertificates))
                .append(new CRLValidator())
                .build()
                .validate(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer"));
    }

    @Test
    public void simpleProdSmp() throws Exception {
        KeystoreCertificateBucket keystoreCertificateBucket = new KeystoreCertificateBucket("JKS", getClass().getResourceAsStream("/peppol-prod.jks"), "peppol");
        CertificateBucket rootCertificates = keystoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keystoreCertificateBucket.toSimple("peppol-ap");

        ValidatorBuilder.newInstance()
                .append(new ExpirationValidator())
                .append(new PrincipalNameValidator("CN", new SimplePrincipalNameProvider("PEPPOL SERVICE METADATA PUBLISHER CA"), PrincipalNameValidator.Principal.ISSUER))
                .append(new Chain2Validator(rootCertificates, intermediateCertificates))
                // .append(new OCSPValidator(intermediateCertificates))
                .append(new CRLValidator())
                .build()
                .validate(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer"));
    }
}
