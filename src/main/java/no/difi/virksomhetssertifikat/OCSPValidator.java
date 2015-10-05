package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.provider.certpath.OCSP;

import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

/**
 * Validation of certificate using OCSP. Requires intermediate certificates.
 */
public class OCSPValidator implements CertificateValidator {

    private static final Logger logger = LoggerFactory.getLogger(OCSPValidator.class);

    private CertificateBucket intermediateCertificates;

    public OCSPValidator(CertificateBucket intermediateCertificates) {
        this.intermediateCertificates = intermediateCertificates;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        try {
            X509Certificate issuer = intermediateCertificates.findBySubject(certificate.getIssuerX500Principal());
            if (issuer == null)
                throw new FailedValidationException(String.format("Unable to find issuer certificate '%s'", certificate.getIssuerX500Principal().getName()));

            OCSP.RevocationStatus status = getRevocationStatus(certificate, issuer);

            if (!status.getCertStatus().equals(OCSP.RevocationStatus.CertStatus.GOOD))
                throw new FailedValidationException("Certificate status is not reported as GOOD by OCSP.");
        } catch (CertificateValidationException e) {
            logger.debug("{} ({})", e.getMessage(), certificate.getSerialNumber());
            throw e;
        } catch (Exception e) {
            logger.debug("{} ({})", e.getMessage(), certificate.getSerialNumber());
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }

    public OCSP.RevocationStatus getRevocationStatus(X509Certificate cert, X509Certificate issuer) throws IOException, CertPathValidatorException {
        return OCSP.check(cert, issuer);
    }
}
