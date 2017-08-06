package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.FailedValidationException;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Validate validity of certificate.
 */
public class ExpirationRule extends AbstractRule {

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws FailedValidationException {
        try {
            certificate.checkValidity(new Date());
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            throw new FailedValidationException("Certificate does not have a valid expiration date.");
        }
    }
}
