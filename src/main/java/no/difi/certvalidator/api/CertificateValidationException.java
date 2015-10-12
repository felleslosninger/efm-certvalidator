package no.difi.certvalidator.api;

/**
 * Generic exception for project.
 */
public class CertificateValidationException extends Exception {
    public CertificateValidationException(String reason, Throwable cause) {
        super(reason, cause);
    }

    public CertificateValidationException(String message) {
        super(message);
    }
}
