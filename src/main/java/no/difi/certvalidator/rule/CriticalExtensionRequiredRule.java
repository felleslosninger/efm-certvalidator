package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;


public class CriticalExtensionRequiredRule extends AbstractRule {

    private List<String> requiredExtensions;

    public CriticalExtensionRequiredRule(String... requiredExtensions) {
        this.requiredExtensions = Arrays.asList(requiredExtensions);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        Set<String> oids = certificate.getCriticalExtensionOIDs();

        if (oids == null)
            throw new FailedValidationException("Certificate doesn't contain critical OIDs.");

        for (String oid : requiredExtensions)
            if (!oids.contains(oid))
                throw new FailedValidationException(String.format("Certificate doesn't contain critical OID '%s'.", oid));
    }
}
