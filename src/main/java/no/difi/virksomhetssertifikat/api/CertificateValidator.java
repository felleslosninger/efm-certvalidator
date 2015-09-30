package no.difi.virksomhetssertifikat.api;

import java.security.cert.X509Certificate;

public interface CertificateValidator {

    boolean isValid(X509Certificate cert) throws CertificateValidationException;
    String faultMessage(X509Certificate cert);
}
