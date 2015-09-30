package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidator;
import no.difi.virksomhetssertifikat.api.CertificateValidationException;

import java.security.cert.X509Certificate;

/**
 * Combine multiple validators into one validator.
 */
public class SuiteValidator implements CertificateValidator {

    private CertificateValidator[] certificateValidators;

    public SuiteValidator(CertificateValidator... certificateValidators) {
        this.certificateValidators = certificateValidators;
    }

    public boolean isValid(X509Certificate cert) throws CertificateValidationException {
        for (CertificateValidator certificateValidator : certificateValidators)
            if (!certificateValidator.isValid(cert))
                return false;
        return true;
    }

    public String faultMessage(X509Certificate cert) {
        return "Not available.";
    }
}
