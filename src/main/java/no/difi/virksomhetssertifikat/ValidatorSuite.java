package no.difi.virksomhetssertifikat;

import java.security.cert.X509Certificate;

public class ValidatorSuite implements CertificateValidator {

    private CertificateValidator[] certificateValidators;

    public ValidatorSuite(CertificateValidator... certificateValidators) {
        this.certificateValidators = certificateValidators;
    }

    public boolean isValid(X509Certificate cert) throws VirksomhetsValidationException {
        for (CertificateValidator certificateValidator : certificateValidators)
            if (!certificateValidator.isValid(cert))
                return false;
        return true;
    }

    public String faultMessage(X509Certificate cert) {
        return "Not available.";
    }
}
