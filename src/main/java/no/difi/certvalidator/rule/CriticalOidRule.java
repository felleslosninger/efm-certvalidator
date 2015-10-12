package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.FailedValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;


public class CriticalOidRule implements ValidatorRule {

    private static Logger logger = LoggerFactory.getLogger(CriticalOidRule.class);

    private List<String> approvedOids;

    public CriticalOidRule(String... approvedOids) {
        this.approvedOids = Arrays.asList(approvedOids);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        if(certificate.getCriticalExtensionOIDs() == null)
            throw new FailedValidationException("Certificate doesn't contain critical OIDs.");

        for(String oid : certificate.getCriticalExtensionOIDs()){
            if(!approvedOids.contains(oid)) {
                logger.debug("Certificate doesn't contain critical OID '{}'. ({})", oid, certificate.getSerialNumber());
                throw new FailedValidationException(String.format("Certificate doesn't contain critical OID '%s'.", oid));
            }
        }
    }
 }
