package no.difi.virksomhetssertifikat.rule;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.ValidatorRule;
import no.difi.virksomhetssertifikat.api.FailedValidationException;

import java.security.cert.X509Certificate;

/**
 * Throws an exception on validation if message is set.
 */
public class DummyRule implements ValidatorRule {
    private String message;

    /**
     * Defines an instance always having successful validations.
     */
    public DummyRule() {
        this(null);
    }

    /**
     * Defines as instance always having failing validations, given message is not null.
     * @param message Message used when failing validation.
     */
    public DummyRule(String message) {
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
