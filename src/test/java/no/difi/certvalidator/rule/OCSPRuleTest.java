package no.difi.certvalidator.rule;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.CertificateBucket;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.util.KeyStoreCertificateBucket;
import no.difi.certvalidator.util.SimpleCertificateBucket;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

public class OCSPRuleTest {

    /**
     * OCSP should be tested only for certificates containing such information, just like CRL.
     */
    @Test
    public void certificateWithoutOCSP() throws CertificateValidationException {
        X509Certificate certificate = Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer"));
        ValidatorRule rule = new OCSPRule(new SimpleCertificateBucket(certificate));
        rule.validate(certificate);
    }

    @Test
    public void certificateWithOCSP() throws CertificateValidationException {
        KeyStoreCertificateBucket keyStoreCertificateBucket = new KeyStoreCertificateBucket("JKS", getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        ValidatorRule rule = new OCSPRule(keyStoreCertificateBucket.toSimple("peppol-ap", "peppol-smp"));
        rule.validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer")));
    }
}
