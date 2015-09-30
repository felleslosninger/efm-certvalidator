package no.difi.virksomhetssertifikat;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class VirksomhetExpirationDateValidator implements CertificateValidator {
    public boolean isValid(X509Certificate cert) {
        try{
            cert.checkValidity(new Date());
        }catch (CertificateNotYetValidException e){
            return false;
        }catch (CertificateExpiredException e){
            return false;
        }

        return true;
    }

    public String faultMessage(X509Certificate cert) {
        return "Certificate does not have a valid expiration date";
    }
}
