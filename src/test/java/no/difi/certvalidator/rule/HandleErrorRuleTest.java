package no.difi.certvalidator.rule;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.*;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

public class HandleErrorRuleTest {

    @Test
    public void simpleOk() throws CertificateValidationException {
        new Validator(new HandleErrorRule(new DummyRule()))
                .validate(getClass().getResourceAsStream("/selfsigned.cer"));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void simpleFailed() throws CertificateValidationException {
        new Validator(new HandleErrorRule(new DummyRule("Trigger me!")))
                .validate(getClass().getResourceAsStream("/selfsigned.cer"));
    }

    @Test
    public void simpleUnknown() throws CertificateValidationException {
        new Validator(new HandleErrorRule(new ValidatorRule() {
            @Override
            public void validate(X509Certificate certificate) throws CertificateValidationException {
                throw new CertificateValidationException("Unable to load something...");
            }

            @Override
            public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
                throw new CertificateValidationException("Unable to load something...");
            }
        }))
                .validate(getClass().getResourceAsStream("/selfsigned.cer"));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void triggerException() throws CertificateValidationException {
        new Validator(new HandleErrorRule(new ErrorHandler() {
            @Override
            public void handle(CertificateValidationException e) throws FailedValidationException {
                throw new FailedValidationException(e.getMessage(), e);
            }
        }, new ValidatorRule() {
            @Override
            public void validate(X509Certificate certificate) throws CertificateValidationException {
                throw new CertificateValidationException("Test");
            }

            @Override
            public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
                throw new CertificateValidationException("Test");
            }
        }))
                .validate(getClass().getResourceAsStream("/selfsigned.cer"));
    }
}
