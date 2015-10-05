package no.difi.virksomhetssertifikat.api;

import java.security.cert.X509Certificate;

/**
 * Defines a validator instance. Made as simple as possible by purpose.
 */
public interface CertificateValidator {
    /**
     * Validate certificate.
     * @param certificate Certificate subject to validation.
     * @throws CertificateValidationException
     */
    void validate(X509Certificate certificate) throws CertificateValidationException;
}
