package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
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

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        // TODO Burde ikke mangel på oids ende med feilet test?
        if(certificate.getCriticalExtensionOIDs() == null)
            return;

        for(String oid : certificate.getCriticalExtensionOIDs()){
            if(!approvedOids.contains(oid)) {
                logger.debug("Certificate doesn't contain critical OID '{}'. ({})", oid, certificate.getSerialNumber());
                throw new FailedValidationException(String.format("Certificate doesn't contain critical OID '%s'.", oid));
            }
        }
    }

    /*
    public String faultMessage() {
        return "Certificate has critical extentions that isnt handled";
    }
    */
}
