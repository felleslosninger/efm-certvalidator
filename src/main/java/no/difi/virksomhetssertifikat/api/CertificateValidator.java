package no.difi.virksomhetssertifikat.api;

import java.security.cert.X509Certificate;

public interface CertificateValidator {
    void validate(X509Certificate cert) throws CertificateValidationException;
}
