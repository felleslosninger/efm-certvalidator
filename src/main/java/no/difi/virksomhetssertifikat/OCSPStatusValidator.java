package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidator;
import sun.security.provider.certpath.OCSP;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class OCSPStatusValidator implements CertificateValidator {

    private DifiKeyStoreUtil difiKeyStoreUtil;

    public DifiKeyStoreUtil getDifiKeyStoreUtil() {
        return difiKeyStoreUtil;
    }

    public void setDifiKeyStoreUtil(DifiKeyStoreUtil difiKeyStoreUtil) {
        this.difiKeyStoreUtil = difiKeyStoreUtil;
    }

    public OCSPStatusValidator(DifiKeyStoreUtil difiKeyStoreUtil) {
        this.difiKeyStoreUtil = difiKeyStoreUtil;
    }

    public boolean isValid(X509Certificate cert) {
        try {
            KeyStore ks = getDifiKeyStoreUtil().loadCaCertsKeystore();

            X509Certificate issuer = getCertsIssuerCertificate(ks, cert.getIssuerX500Principal());

            OCSP.RevocationStatus status = getRevocationStatus(cert, issuer);

            return status.getCertStatus().equals(OCSP.RevocationStatus.CertStatus.GOOD);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    protected X509Certificate getCertsIssuerCertificate(KeyStore ks, X500Principal issuerX500Principal) throws KeyStoreException {
        X509Certificate issuer = null;

        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements() && issuer == null){
            String alias = aliases.nextElement();
            X509Certificate possibleIssuer = (X509Certificate) ks.getCertificate(alias);
            if(possibleIssuer.getSubjectX500Principal().equals(issuerX500Principal)){
                issuer = possibleIssuer;
            }
        }
        return issuer;
    }

    public OCSP.RevocationStatus getRevocationStatus(X509Certificate cert, X509Certificate issuer) throws IOException, CertPathValidatorException {
        return OCSP.check(cert, issuer);
    }

    @Override
    public String faultMessage(X509Certificate cert) {
        return "Not available";
    }
}
