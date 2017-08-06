package no.difi.certvalidator;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.Property;
import no.difi.certvalidator.api.Report;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.util.DummyReport;
import no.difi.certvalidator.util.SimpleProperty;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Encapsulate validator for a more extensive API.
 */
public class Validator implements ValidatorRule {

    public static final Property<X509Certificate> CERTIFICATE = SimpleProperty.create();

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
        validate(certificate, DummyReport.INSTANCE);
    }

    @Override
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        return validatorRule.validate(certificate, report);
    }

    public X509Certificate validate(InputStream inputStream) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(inputStream);
        validate(certificate);
        return certificate;
    }

    public Report validate(InputStream inputStream, Report report) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(inputStream);
        validate(certificate, report);

        report.set(CERTIFICATE, certificate);

        return report;
    }

    public X509Certificate validate(byte[] bytes) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(bytes);
        validate(certificate);
        return certificate;
    }

    public Report validate(byte[] bytes, Report report) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(bytes);
        validate(certificate, report);

        report.set(CERTIFICATE, certificate);

        return report;
    }

    public boolean isValid(X509Certificate certificate) {
        try {
            validate(certificate, DummyReport.INSTANCE);
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
