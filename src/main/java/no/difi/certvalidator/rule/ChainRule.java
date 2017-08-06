package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.*;
import no.difi.certvalidator.util.BCHelper;
import no.difi.certvalidator.util.SimpleProperty;

import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Validator checking validity of chain using root certificates and intermediate certificates.
 */
public class ChainRule extends AbstractRule {

    public static final Property<List<? extends Certificate>> PATH = SimpleProperty.create();

    public static final Property<X509Certificate> ANCHOR = SimpleProperty.create();

    private CertificateBucket rootCertificates;

    private CertificateBucket intermediateCertificates;

    private Set<String> policies = new HashSet<>();

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
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        try {
            PKIXCertPathBuilderResult result = verifyCertificate(certificate);

            report.set(ANCHOR, result.getTrustAnchor().getTrustedCert());
            report.set(PATH, result.getCertPath().getCertificates());

            return report;
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
        Set<TrustAnchor> trustAnchors = new HashSet<>();
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
        Set<X509Certificate> trustedIntermediateCert = new HashSet<>();
        for (X509Certificate certificate : intermediateCertificates) {
            trustedIntermediateCert.add(certificate);
        }
        trustedIntermediateCert.add(cert);

        pkixParams.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(trustedIntermediateCert), BCHelper.PROVIDER));

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", BCHelper.PROVIDER);
        return (PKIXCertPathBuilderResult) builder.build(pkixParams);
    }
}
