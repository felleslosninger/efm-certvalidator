package no.difi.virksomhetssertifikat.rule;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.ValidatorRule;
import no.difi.virksomhetssertifikat.api.FailedValidationException;

import java.security.cert.X509Certificate;

/**
 * Validation making sure certificate doesn't expire in n milliseconds.
 */
public class ExpirationSoonRule implements ValidatorRule {

    private long millis;

    public ExpirationSoonRule(long millis) {
        this.millis = millis;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        if (certificate.getNotAfter().getTime() < (System.currentTimeMillis() + millis))
            throw new FailedValidationException(String.format("Certificate expires in less than %s milliseconds.", millis));
    }
}
