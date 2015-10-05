package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.*;

public class Chain2Validator implements CertificateValidator {

    private static Logger logger = LoggerFactory.getLogger(Chain2Validator.class);

    private CertificateBucket rootCertificates;
    private CertificateBucket intermediateCertificates;

    public Chain2Validator(CertificateBucket rootCertificates, CertificateBucket intermediateCertificates) {
        this.rootCertificates = rootCertificates;
        this.intermediateCertificates = intermediateCertificates;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        try {
            PKIXCertPathBuilderResult result = verifyCertificate(certificate);
        } catch (GeneralSecurityException e) {
            logger.debug(e.getMessage(), e);
        }
    }

    /**
     * Source: http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
     */
    private PKIXCertPathBuilderResult verifyCertificate(X509Certificate cert) throws GeneralSecurityException {

        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate trustedRootCert : rootCertificates) {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);

        // Specify a list of intermediate certificates
        List<X509Certificate> trustedIntermediateCert = new ArrayList<>();
        for (X509Certificate certificate : intermediateCertificates)
            trustedIntermediateCert.add(certificate);
        pkixParams.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(trustedIntermediateCert), "BC"));

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
        return (PKIXCertPathBuilderResult) builder.build(pkixParams);
    }
}
