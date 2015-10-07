package no.difi.virksomhetssertifikat.usage;

import no.difi.virksomhetssertifikat.*;
import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.api.CrlCache;
import no.difi.virksomhetssertifikat.rule.*;
import no.difi.virksomhetssertifikat.util.KeyStoreCertificateBucket;
import no.difi.virksomhetssertifikat.util.SimpleCrlCache;
import no.difi.virksomhetssertifikat.util.SimplePrincipalNameProvider;
import org.testng.annotations.Test;

public class PeppolTest {

    private CrlCache crlCache = new SimpleCrlCache();

    @Test
    public void simpleTestAp() throws Exception {
        KeyStoreCertificateBucket keyStoreCertificateBucket = new KeyStoreCertificateBucket(getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        CertificateBucket rootCertificates = keyStoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keyStoreCertificateBucket.toSimple("peppol-ap", "peppol-smp");

        Validator validatorHelper = ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(new SigningRule())
                .addRule(new PrincipalNameRule("CN", new SimplePrincipalNameProvider("PEPPOL ACCESS POINT TEST CA"), PrincipalNameRule.Principal.ISSUER))
                .addRule(new ChainRule(rootCertificates, intermediateCertificates))
                .addRule(new CRLRule(crlCache))
                //.addRule(new OCSPRule(intermediateCertificates))
                .build();

        validatorHelper.validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
        validatorHelper.validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }

    @Test
    public void simpleTestSmp() throws Exception {
        KeyStoreCertificateBucket keyStoreCertificateBucket = new KeyStoreCertificateBucket(getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        CertificateBucket rootCertificates = keyStoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keyStoreCertificateBucket.toSimple("peppol-ap", "peppol-smp");

        ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(new SigningRule())
                .addRule(new PrincipalNameRule("CN", new SimplePrincipalNameProvider("PEPPOL SERVICE METADATA PUBLISHER TEST CA"), PrincipalNameRule.Principal.ISSUER))
                .addRule(new ChainRule(rootCertificates, intermediateCertificates))
                .addRule(new CRLRule(crlCache))
                //.addRule(new OCSPRule(intermediateCertificates))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer"));
    }

    @Test
    public void simpleProdAp() throws Exception {
        KeyStoreCertificateBucket keyStoreCertificateBucket = new KeyStoreCertificateBucket(getClass().getResourceAsStream("/peppol-prod.jks"), "peppol");
        CertificateBucket rootCertificates = keyStoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keyStoreCertificateBucket.toSimple("peppol-ap", "peppol-smp");

        ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(new SigningRule())
                .addRule(new PrincipalNameRule("CN", new SimplePrincipalNameProvider("PEPPOL ACCESS POINT CA"), PrincipalNameRule.Principal.ISSUER))
                .addRule(new ChainRule(rootCertificates, intermediateCertificates))
                .addRule(new CRLRule(crlCache))
                .addRule(new OCSPRule(intermediateCertificates))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer"));
    }

    @Test
    public void simpleProdSmp() throws Exception {
        KeyStoreCertificateBucket keyStoreCertificateBucket = new KeyStoreCertificateBucket(getClass().getResourceAsStream("/peppol-prod.jks"), "peppol");
        CertificateBucket rootCertificates = keyStoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keyStoreCertificateBucket.toSimple("peppol-ap", "peppol-smp");

        ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(new SigningRule())
                .addRule(new PrincipalNameRule("CN", new SimplePrincipalNameProvider("PEPPOL SERVICE METADATA PUBLISHER CA"), PrincipalNameRule.Principal.ISSUER))
                .addRule(new ChainRule(rootCertificates, intermediateCertificates))
                .addRule(new CRLRule(crlCache))
                .addRule(new OCSPRule(intermediateCertificates))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer"));
    }
}
