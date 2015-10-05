package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.HashSet;
import java.util.Set;

public class Chain2Validator implements CertificateValidator {

    private static Logger logger = LoggerFactory.getLogger(Chain2Validator.class);

    /* static {
        Security.addProvider(new BouncyCastleProvider());
    } */

    private CertificateBucket rootCertificates;
    private CertificateBucket intermediateCertificates;

    /**
     *
     * @param rootCertificates Trusted root certificates.
     * @param intermediateCertificates Trusted intermediate certificates.
     */
    public Chain2Validator(CertificateBucket rootCertificates, CertificateBucket intermediateCertificates) {
        this.rootCertificates = rootCertificates;
        this.intermediateCertificates = intermediateCertificates;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        try {
            PKIXCertPathBuilderResult result = verifyCertificate(certificate);
            for (Certificate c : result.getCertPath().getCertificates())
                logger.debug("({}) | {}", certificate.getSerialNumber(), ((X509Certificate) c).getSubjectX500Principal().getName());
        } catch (GeneralSecurityException e) {
            logger.debug("({}) {}", certificate.getSerialNumber(), e.getMessage());
            throw new FailedValidationException(e.getMessage(), e);
        }
    }

    /**
     * Source: http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
     */
    private PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert) throws GeneralSecurityException {
        logger.debug("({}) Chain: {}", cert.getSerialNumber(), cert.getSubjectX500Principal().getName());

        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate trustedRootCert : rootCertificates) {
            logger.debug("({}) Trusted: {}", cert.getSerialNumber(), trustedRootCert.getSubjectDN().getName());
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);

        // From old validator. Needed?
        // Set<String> initialPolicies = new HashSet<String>();
        // initialPolicies.addAll(policyProvider.getApproprovedPolicyOids());
        // pkixParams.setInitialPolicies(initialPolicies);
        // spkixParams.setExplicitPolicyRequired(true);

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);

        // Specify a list of intermediate certificates
        Set<X509Certificate> trustedIntermediateCert = new HashSet<>();
        for (X509Certificate certificate : intermediateCertificates) {
            logger.debug("({}) Intermediate: {}", cert.getSerialNumber(), certificate.getSubjectDN().getName());
            trustedIntermediateCert.add(certificate);
        }
        pkixParams.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(trustedIntermediateCert))); //, BouncyCastleProvider.PROVIDER_NAME));

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX"); // , BouncyCastleProvider.PROVIDER_NAME);
        return (PKIXCertPathBuilderResult) builder.build(pkixParams);
    }
}
