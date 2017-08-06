package no.difi.certvalidator.api;

import java.security.cert.X509Certificate;

/**
 * Defines a validator rule. Made as simple as possible by purpose.
 */
public interface ValidatorRule {

    /**
     * Validate certificate.
     * @param certificate Certificate subject to validation.
     * @throws CertificateValidationException
     */
    void validate(X509Certificate certificate) throws CertificateValidationException;

    /**
     * Validate certificate.
     * @param certificate Certificate subject to validation.
     * @param report Report to be filled during validation.
     * @throws CertificateValidationException
     */
    Report validate(X509Certificate certificate, Report report) throws CertificateValidationException;
}
