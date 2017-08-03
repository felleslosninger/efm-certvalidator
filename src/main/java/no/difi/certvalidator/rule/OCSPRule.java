package no.difi.certvalidator.rule;

import net.klakegg.pkix.ocsp.OcspClient;
import net.klakegg.pkix.ocsp.OcspException;
import no.difi.certvalidator.api.CertificateBucket;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.ValidatorRule;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author erlend
 */
public class OCSPRule implements ValidatorRule {

    protected OcspClient ocspClient;

    public OCSPRule(CertificateBucket intermediateCertificates) {
        List<X509Certificate> intermediates = new ArrayList<>();

        for (X509Certificate intermediateCertificate : intermediateCertificates)
            intermediates.add(intermediateCertificate);

        ocspClient = OcspClient.builder()
                .set(OcspClient.INTERMEDIATES, intermediates)
                .build();
    }

    public OCSPRule(OcspClient ocspClient) {
        this.ocspClient = ocspClient;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        try {
            ocspClient.verify(certificate);
        } catch (OcspException e) {
            throw new FailedValidationException(e.getMessage(), e);
        } catch (Exception e) {
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }
}
