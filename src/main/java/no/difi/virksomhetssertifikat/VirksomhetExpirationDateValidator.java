package no.difi.virksomhetssertifikat;

import org.joda.time.DateTime;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class VirksomhetExpirationDateValidator implements DifiSecurityValidator{
    public boolean isValid(X509Certificate cert) {
        try{
            cert.checkValidity(DateTime.now().toDate());
        }catch (CertificateNotYetValidException e){
            return false;
        }catch (CertificateExpiredException e){
            return false;
        }

        return true;
    }

    @Override
    public String faultMessage(X509Certificate cert) {
        return "Certificate does not have a valid expiration date";
    }
}
