package no.difi.virksomhetssertifikat.api;

import java.security.cert.X509Certificate;

public interface CertificateValidator {
    /**
     * Validate certificate.
     * @param certificate Certificate subject to validation.
     * @throws CertificateValidationException
     */
    void validate(X509Certificate certificate) throws CertificateValidationException;
}
