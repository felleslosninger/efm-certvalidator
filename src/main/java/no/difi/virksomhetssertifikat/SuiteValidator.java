package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;

import java.security.cert.X509Certificate;

/**
 * Combine multiple validators into one validator.
 */
public class SuiteValidator implements CertificateValidator {

    private CertificateValidator[] certificateValidators;

    public SuiteValidator(CertificateValidator... certificateValidators) {
        this.certificateValidators = certificateValidators;
    }

    public void validate(X509Certificate cert) throws CertificateValidationException {
        for (CertificateValidator certificateValidator : certificateValidators)
            certificateValidator.validate(cert);
    }
}
