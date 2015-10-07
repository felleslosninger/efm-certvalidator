package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.ValidatorRule;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Validate validity of certificate.
 */
public class ExpirationRule implements ValidatorRule {

    private static final Logger logger = LoggerFactory.getLogger(ExpirationRule.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws FailedValidationException {
        try {
            certificate.checkValidity(new Date());
        } catch (CertificateNotYetValidException e) {
            logger.debug("Certificate not yet valid. ({})", certificate.getSerialNumber());
            throw new FailedValidationException("Certificate does not have a valid expiration date.");
        } catch (CertificateExpiredException e) {
            logger.debug("Certificate expired. ({})", certificate.getSerialNumber());
            throw new FailedValidationException("Certificate does not have a valid expiration date.");
        }
    }
}
