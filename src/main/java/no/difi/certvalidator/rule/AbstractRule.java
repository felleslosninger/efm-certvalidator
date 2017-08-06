package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.Report;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.util.DummyReport;

import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public abstract class AbstractRule implements ValidatorRule {

    @Override
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        validate(certificate);
        
        return report;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        validate(certificate, DummyReport.INSTANCE);
    }
}
