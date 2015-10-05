package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;
import no.difi.virksomhetssertifikat.api.FailedValidationException;

import java.security.cert.X509Certificate;

public class ExpirationSoonValidator implements CertificateValidator {

    private long millis;

    public ExpirationSoonValidator(long millis) {
        this.millis = millis;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        if (certificate.getNotAfter().getTime() < (System.currentTimeMillis() + millis))
            throw new FailedValidationException(String.format("Certificate expires in less than %s milliseconds.", millis));
    }
}
