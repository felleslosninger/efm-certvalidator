package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class CriticalExtensionRecognizedRule extends AbstractRule {

    private final List<String> recognizedExtensions;

    public CriticalExtensionRecognizedRule(String... recognizedExtensions) {
        this.recognizedExtensions = Arrays.asList(recognizedExtensions);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        Set<String> oids = certificate.getCriticalExtensionOIDs();

        if (oids == null)
            return;

        for (String oid : oids) {
            if (!recognizedExtensions.contains(oid)) {
                throw new FailedValidationException(String.format(
                        "X509 certificate %s specifies a critical extension %s which is not recognized",
                        certificate.getSerialNumber(),
                        oid
                ));
            }
        }
    }
}
