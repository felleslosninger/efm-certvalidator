package no.difi.certvalidator.usage;

import no.difi.certvalidator.*;
import no.difi.certvalidator.api.CertificateBucket;
import no.difi.certvalidator.api.CrlCache;
import no.difi.certvalidator.rule.*;
import no.difi.certvalidator.util.KeyStoreCertificateBucket;
import no.difi.certvalidator.util.SimpleCrlCache;
import no.difi.certvalidator.util.SimplePrincipalNameProvider;
import org.testng.annotations.Test;

public class PeppolTest {

    private CrlCache crlCache = new SimpleCrlCache();

    @Test(enabled = false)
    public void simpleTestAp() throws Exception {
        KeyStoreCertificateBucket keyStoreCertificateBucket = new KeyStoreCertificateBucket(getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        CertificateBucket rootCertificates = keyStoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keyStoreCertificateBucket.toSimple("peppol-ap", "peppol-smp");

        Validator valvalidatordatorHelper = ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(new SigningRule())
                .addRule(new PrincipalNameRule("CN", new SimplePrincipalNameProvider("PEPPOL ACCESS POINT TEST CA"), PrincipalNameRule.Principal.ISSUER))
                .addRule(new ChainRule(rootCertificates, intermediateCertificates))
                .addRule(new CRLRule(crlCache))
                .addRule(new OCSPRule(intermediateCertificates))
                .build();

        valvalidatordatorHelper.validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
        valvalidatordatorHelper.validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }

    @Test(enabled = false)
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
                .addRule(new OCSPRule(intermediateCertificates))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer"));
    }

    @Test(enabled = false)
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

    @Test(enabled = false)
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
