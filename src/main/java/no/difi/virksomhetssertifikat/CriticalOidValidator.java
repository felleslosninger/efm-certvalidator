package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;


public class CriticalOidValidator implements CertificateValidator {

    private static Logger logger = LoggerFactory.getLogger(CriticalOidValidator.class);

    private List<String> approvedOids;

    public CriticalOidValidator(String... approvedOids) {
        this.approvedOids = Arrays.asList(approvedOids);
    }

    public boolean isValid(X509Certificate cert) {
        // TODO Burde ikke mangel på oids ende med feilet test?
        if(cert.getCriticalExtensionOIDs() == null)
            return true;

        for(String oid : cert.getCriticalExtensionOIDs()){
            if(!approvedOids.contains(oid)) {
                logger.debug("Certificate doesn't contain critical OID '{}'. ({})", oid, cert.getSerialNumber());
                return false;
            }
        }

        return true;
    }

    public String faultMessage(X509Certificate cert) {
        return "Certificate has critical extentions that isnt handled";
    }
}
