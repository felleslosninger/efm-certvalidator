package no.difi.certvalidator.api;

/**
 * Exception related to actions performed by certificate buckets.
 */
public class CertificateBucketException extends CertificateValidationException {
    public CertificateBucketException(String reason, Throwable cause) {
        super(reason, cause);
    }
}
