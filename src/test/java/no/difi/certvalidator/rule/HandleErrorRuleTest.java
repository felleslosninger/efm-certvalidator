package no.difi.certvalidator.rule;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.Report;
import no.difi.certvalidator.api.ValidatorRule;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

public class HandleErrorRuleTest {

    @Test
    public void simpleOk() throws CertificateValidationException {
        new HandleErrorRule(new DummyRule())
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void simpleFailed() throws CertificateValidationException {
        new HandleErrorRule(new DummyRule("Trigger me!"))
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }

    @Test
    public void simpleUnknown() throws CertificateValidationException {
        new HandleErrorRule(new ValidatorRule() {
            @Override
            public void validate(X509Certificate certificate) throws CertificateValidationException {
                throw new CertificateValidationException("Unable to load something...");
            }

            @Override
            public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
                throw new CertificateValidationException("Unable to load something...");
            }
        })
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }
}
