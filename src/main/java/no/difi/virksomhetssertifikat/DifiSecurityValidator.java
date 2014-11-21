package no.difi.virksomhetssertifikat;

import java.security.cert.X509Certificate;

public interface DifiSecurityValidator {

    public boolean isValid(X509Certificate cert) throws VirksomhetsValidationException;
    public String faultMessage(X509Certificate cert);
}
