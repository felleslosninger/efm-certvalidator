package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;

import java.security.cert.X509Certificate;

public class CRLValidator implements CertificateValidator {

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {

    }
}
