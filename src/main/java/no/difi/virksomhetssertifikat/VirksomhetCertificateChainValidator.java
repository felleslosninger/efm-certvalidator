package no.difi.virksomhetssertifikat;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;


public class VirksomhetCertificateChainValidator implements CertificateValidator {
    private DifiKeyStoreUtil difiKeystoreUtil;
    private AcceptedCertificatePolicyProvider policyProvider;

    public VirksomhetCertificateChainValidator() {
    }

    public VirksomhetCertificateChainValidator(DifiKeyStoreUtil difiKeystoreUtil, AcceptedCertificatePolicyProvider policyProvider) {
        this.difiKeystoreUtil = difiKeystoreUtil;
        this.policyProvider = policyProvider;
    }

    public boolean isValid(X509Certificate cert) throws VirksomhetsValidationException {
        CertPath certPath;
        CertStore intermadiate;
        Set<TrustAnchor> trustAnchors;
        try{
            intermadiate = CertStore.getInstance("Collection", new CollectionCertStoreParameters(
                getAllCerts(difiKeystoreUtil.loadIntermediateCertsKeystore())
            ));

            trustAnchors = getTrustAnchors(difiKeystoreUtil.loadCaCertsKeystore());
            certPath = getCertPath(trustAnchors, intermadiate, cert );
        }catch(Exception e){
            throw new VirksomhetsValidationException("Could not build trusted certificate path", e);
        }

        try{

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");

            // Legge inn tiltrodde rotsertifikater
            PKIXParameters params = new PKIXParameters(trustAnchors);

            // Gjøre tilgjengelig mellomliggende sertifikater
            params.addCertStore(intermadiate);

            Set<String> initialPolicies = new HashSet<String>();
            initialPolicies.addAll(policyProvider.getApproprovedPolicyOids());
            params.setInitialPolicies(initialPolicies);
            params.setExplicitPolicyRequired(true);

            //gjøres i egen sjekk
            params.setRevocationEnabled(false);

            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, params);

            return true;
        }catch(Exception e){
            throw new VirksomhetsValidationException("Could validate certificate", e);
        }

    }

    public String faultMessage(X509Certificate cert) {
        return "Certificate chain not valid";
    }

    private Collection<? extends Certificate> getAllCerts(KeyStore ks) throws KeyStoreException {
        List<Certificate> intermediates = new ArrayList<Certificate>();
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements()){
            Certificate certificate = ks.getCertificate(aliases.nextElement());
            intermediates.add(certificate);
        }
        return intermediates;
    }

    private CertPath getCertPath(Set<TrustAnchor> trustAnchors, CertStore intermediateCa, Certificate target) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertPathBuilderException {
        CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate((X509Certificate) target);

        PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, selector);
        params.setRevocationEnabled(false);
        params.addCertStore(intermediateCa);
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) certPathBuilder.build(params);
        return result.getCertPath();
    }

    public Set<TrustAnchor> getTrustAnchors(KeyStore ks) throws KeyStoreException {
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements()){
            Certificate certificate = ks.getCertificate(aliases.nextElement());
            anchors.add(new TrustAnchor((X509Certificate) certificate, null));
        }
        return anchors;
    }


}