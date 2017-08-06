package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;

import java.security.cert.X509Certificate;

/**
 * Throws an exception on validation if message is set.
 */
public class DummyRule extends AbstractRule {

    public static DummyRule alwaysSuccess() {
        return new DummyRule();
    }

    public static DummyRule alwaysFail(String message) {
        return new DummyRule(message);
    }

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
