package no.difi.virksomhetssertifikat.api;

public class CertificateBucketException extends CertificateValidationException {
    public CertificateBucketException(String reason, Throwable cause) {
        super(reason, cause);
    }
}
