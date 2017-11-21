package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateBucket;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;

import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public class WhitelistRule extends AbstractRule {

    private final CertificateBucket certificates;

    public WhitelistRule(CertificateBucket certificates) {
        this.certificates = certificates;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        for (X509Certificate cert : certificates) {
            if (cert.equals(certificate))
                return;
        }

        throw new FailedValidationException("Certificate is not in whitelist.");
    }
}
