package no.difi.virksomhetssertifikat.api;

/**
 * Exception thrown when validation failes.
 */
public class FailedValidationException extends CertificateValidationException {
    public FailedValidationException(String reason, Throwable cause) {
        super(reason, cause);
    }

    public FailedValidationException(String message) {
        super(message);
    }
}
