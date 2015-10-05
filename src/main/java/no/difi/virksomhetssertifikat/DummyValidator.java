package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;
import no.difi.virksomhetssertifikat.api.FailedValidationException;

import java.security.cert.X509Certificate;

/**
 * Throws an exception on validation if message is set.
 */
public class DummyValidator implements CertificateValidator {
    private String message;

    public DummyValidator() {
        this(null);
    }

    public DummyValidator(String message) {
        this.message = message;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        if (message != null)
            throw new FailedValidationException(message);
    }
}
