package no.difi.certvalidator.rule;

import net.klakegg.pkix.ocsp.CertificateResult;
import net.klakegg.pkix.ocsp.OcspClient;
import net.klakegg.pkix.ocsp.OcspException;
import no.difi.certvalidator.api.*;
import no.difi.certvalidator.util.SimpleProperty;

import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author erlend
 */
public class OCSPRule extends AbstractRule {

    public static final Property<CertificateResult> RESULT = SimpleProperty.create();

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
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        try {
            report.set(RESULT, ocspClient.verify(certificate));

            return report;
        } catch (OcspException e) {
            if (e.getCause() instanceof UnknownHostException)
                throw new CertificateValidationException(e.getMessage(), e);
            else
                throw new FailedValidationException(e.getMessage(), e);
        } catch (Exception e) {
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }
}
