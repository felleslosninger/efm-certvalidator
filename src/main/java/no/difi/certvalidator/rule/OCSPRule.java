package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateBucket;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.ValidatorRule;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.provider.certpath.OCSP;

import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

import static sun.security.provider.certpath.OCSP.RevocationStatus.CertStatus;

/**
 * Validation of certificate using OCSP. Requires intermediate certificates.
 */
public class OCSPRule implements ValidatorRule {

    private static final Logger logger = LoggerFactory.getLogger(OCSPRule.class);

    private CertificateBucket intermediateCertificates;

    public OCSPRule(CertificateBucket intermediateCertificates) {
        this.intermediateCertificates = intermediateCertificates;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        try {
            // Certificates without OCSP information is not subject to OCSP validation.
            if (certificate.getExtensionValue(Extension.authorityInfoAccess.getId()) == null)
                return;

            X509Certificate issuer = intermediateCertificates.findBySubject(certificate.getIssuerX500Principal());
            if (issuer == null)
                throw new FailedValidationException(String.format("Unable to find issuer certificate '%s'", certificate.getIssuerX500Principal().getName()));

            CertStatus certStatus = getRevocationStatus(certificate, issuer).getCertStatus();
            if (!certStatus.equals(CertStatus.GOOD))
                throw new FailedValidationException(String.format("Certificate status is reported as %s by OCSP.", certStatus.name()));
        } catch (IOException | CertPathValidatorException | NullPointerException e) {
            logger.debug("{} ({})", e.getMessage(), certificate.getSerialNumber());
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }

    public OCSP.RevocationStatus getRevocationStatus(X509Certificate cert, X509Certificate issuer) throws IOException, CertPathValidatorException {
        return OCSP.check(cert, issuer);
    }
}
