package no.difi.certvalidator;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.Report;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.util.DummyReport;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Map;

public class ValidatorGroup extends Validator {

    private Map<String, ValidatorRule> rulesMap;

    private String name;

    private String version;

    public ValidatorGroup(Map<String, ValidatorRule> rulesMap) {
        super(null);
        this.rulesMap = rulesMap;
    }

    public ValidatorGroup(Map<String, ValidatorRule> rulesMap, String name, String version) {
        this(rulesMap);
        this.name = name;
        this.version = version;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        validate("default", certificate);
    }

    @Override
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        return validate("default", certificate, report);
    }

    @Override
    public X509Certificate validate(InputStream inputStream) throws CertificateValidationException {
        return validate("default", inputStream);
    }

    @Override
    public Report validate(InputStream inputStream, Report report) throws CertificateValidationException {
        return validate("default", inputStream, report);
    }

    @Override
    public X509Certificate validate(byte[] bytes) throws CertificateValidationException {
        return validate("default", bytes);
    }

    @Override
    public Report validate(byte[] bytes, Report report) throws CertificateValidationException {
        return validate("default", bytes, report);
    }

    public void validate(String name, X509Certificate certificate) throws CertificateValidationException {
        validate(name, certificate, DummyReport.INSTANCE);
    }

    public Report validate(String name, X509Certificate certificate, Report report) throws CertificateValidationException {
        if (!this.rulesMap.containsKey(name))
            throw new CertificateValidationException(String.format("Unknown validator '%s'.", name));

        report.set(CERTIFICATE, certificate);

        return this.rulesMap.get(name).validate(certificate, report);
    }

    public X509Certificate validate(String name, InputStream inputStream) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(inputStream);
        validate(name, certificate, DummyReport.INSTANCE);
        return certificate;
    }

    public Report validate(String name, InputStream inputStream, Report report) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(inputStream);
        return validate(name, certificate, report);
    }

    public X509Certificate validate(String name, byte[] bytes) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(bytes);
        validate(name, certificate, DummyReport.INSTANCE);
        return certificate;
    }

    public Report validate(String name, byte[] bytes, Report report) throws CertificateValidationException {
        X509Certificate certificate = getCertificate(bytes);
        return validate(name, certificate, report);
    }

    public boolean isValid(String name, X509Certificate certificate) {
        try {
            validate(name, certificate);
            return true;
        } catch (CertificateValidationException e) {
            return false;
        }
    }

    public boolean isValid(String name, InputStream inputStream) {
        try {
            return isValid(name, getCertificate(inputStream));
        } catch (CertificateValidationException e) {
            return false;
        }
    }

    public boolean isValid(String name, byte[] bytes) {
        try {
            return isValid(name, getCertificate(bytes));
        } catch (CertificateValidationException e) {
            return false;
        }
    }
}
