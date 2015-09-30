package no.difi.virksomhetssertifikat;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;


public class VirksomheCriticalOidValidator implements CertificateValidator {
    private List<String> approvedOids;

    public VirksomheCriticalOidValidator(String... approvedOids) {
        this.approvedOids = Arrays.asList(approvedOids);
    }

    public boolean isValid(X509Certificate cert) {
        if(cert.getCriticalExtensionOIDs() == null)
            return true;

        for(String oid : cert.getCriticalExtensionOIDs()){
            if(!approvedOids.contains(oid))
                return false;
        }

        return true;
    }

    public String faultMessage(X509Certificate cert) {
        return "Certificate has critical extentions that isnt handled";
    }
}
