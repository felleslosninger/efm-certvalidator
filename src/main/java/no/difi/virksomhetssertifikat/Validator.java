package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.ValidatorRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Encapsulate validator for a more extensive API.
 */
public class Validator implements ValidatorRule {

    private static final Logger logger = LoggerFactory.getLogger(Validator.class);

    private static CertificateFactory certFactory;

    public static X509Certificate getCertificate(byte[] cert) throws CertificateValidationException {
        return getCertificate(new ByteArrayInputStream(cert));
    }

    public static X509Certificate getCertificate(InputStream inputStream) throws CertificateValidationException {
        try {
            if (certFactory == null)
                certFactory = CertificateFactory.getInstance("X.509");

            return (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }

    private ValidatorRule validatorRule;

    public Validator(ValidatorRule validatorRule) {
        this.validatorRule = validatorRule;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        validatorRule.validate(certificate);
    }

    public void validate(InputStream inputStream) throws CertificateValidationException {
        validate(getCertificate(inputStream));
    }

    public void validate(byte[] certificate) throws CertificateValidationException {
        validate(getCertificate(certificate));
    }

    public boolean isValid(X509Certificate certificate) {
        try {
            validatorRule.validate(certificate);
            return true;
        } catch (CertificateValidationException e) {
            logger.info(e.getMessage());
            return false;
        }
    }

    public boolean isValid(InputStream inputStream) {
        try {
            return isValid(getCertificate(inputStream));
        } catch (CertificateValidationException e) {
            logger.debug(e.getMessage(), e);
            return false;
        }
    }

    public boolean isValid(byte[] certificate) {
        try {
            return isValid(getCertificate(certificate));
        } catch (CertificateValidationException e) {
            logger.debug(e.getMessage(), e);
            return false;
        }
    }
}
