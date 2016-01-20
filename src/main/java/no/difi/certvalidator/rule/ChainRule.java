package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateBucket;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.ValidatorRule;

import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Validator checking validity of chain using root certificates and intermediate certificates.
 */
public class ChainRule implements ValidatorRule {

    private CertificateBucket rootCertificates;
    private CertificateBucket intermediateCertificates;
    private Set<String> policies = new HashSet<String>();

    /**
     * @param rootCertificates         Trusted root certificates.
     * @param intermediateCertificates Trusted intermediate certificates.
     */
    public ChainRule(CertificateBucket rootCertificates, CertificateBucket intermediateCertificates, String... policies) {
        this.rootCertificates = rootCertificates;
        this.intermediateCertificates = intermediateCertificates;
        this.policies.addAll(Arrays.asList(policies));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        try {
            verifyCertificate(certificate);
        } catch (GeneralSecurityException e) {
            throw new FailedValidationException(e.getMessage(), e);
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
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        for (X509Certificate trustedRootCert : rootCertificates) {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);

        // Setting explicit policy
        if (!policies.isEmpty()) {
            pkixParams.setInitialPolicies(policies);
            pkixParams.setExplicitPolicyRequired(true);
        }

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);

        // Specify a list of intermediate certificates
        Set<X509Certificate> trustedIntermediateCert = new HashSet<X509Certificate>();
        for (X509Certificate certificate : intermediateCertificates) {
            trustedIntermediateCert.add(certificate);
        }

        pkixParams.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(trustedIntermediateCert)));

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        return (PKIXCertPathBuilderResult) builder.build(pkixParams);
    }
}
