package no.difi.certvalidator;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.ValidatorRule;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Encapsulate validator for a more extensive API.
 */
public class Validator implements ValidatorRule {

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

    public X509Certificate validate(InputStream inputStream) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(inputStream);
        validate(certificate);
        return certificate;
    }

    public X509Certificate validate(byte[] bytes) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(bytes);
        validate(certificate);
        return certificate;
    }

    public boolean isValid(X509Certificate certificate) {
        try {
            validate(certificate);
            return true;
        } catch (CertificateValidationException e) {
            return false;
        }
    }

    public boolean isValid(InputStream inputStream) {
        try {
            return isValid(getCertificate(inputStream));
        } catch (CertificateValidationException e) {
            return false;
        }
    }

    public boolean isValid(byte[] bytes) {
        try {
            return isValid(getCertificate(bytes));
        } catch (CertificateValidationException e) {
            return false;
        }
    }
}
