package no.difi.certvalidator.rule;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.util.KeyStoreCertificateBucket;
import no.difi.certvalidator.util.SimpleCertificateBucket;
import org.mockito.Mockito;
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

    @Test(enabled = false)
    public void certificateWithOCSP() throws CertificateValidationException {
        KeyStoreCertificateBucket keyStoreCertificateBucket = new KeyStoreCertificateBucket("JKS", getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        ValidatorRule rule = new OCSPRule(keyStoreCertificateBucket.toSimple("peppol-ap", "peppol-smp"));
        rule.validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer")));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void issuerNotFound() throws CertificateValidationException {
        ValidatorRule validatorRule = new OCSPRule(new SimpleCertificateBucket());
        new Validator(validatorRule).validate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer"));
    }

    @Test(expectedExceptions = CertificateValidationException.class)
    public void triggerException() throws Exception {
        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        Mockito.doThrow(new NullPointerException()).when(certificate).getExtensionValue(Mockito.anyString());

        ValidatorRule validatorRule = new OCSPRule(new SimpleCertificateBucket());
        validatorRule.validate(certificate);
    }
}
