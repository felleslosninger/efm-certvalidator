package no.difi.virksomhetssertifikat.api;

/**
 * Exception related to actions performed by certificate buckets.
 */
public class CertificateBucketException extends CertificateValidationException {
    public CertificateBucketException(String reason, Throwable cause) {
        super(reason, cause);
    }
}
