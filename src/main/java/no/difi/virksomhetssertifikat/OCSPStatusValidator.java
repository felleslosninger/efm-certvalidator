package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.provider.certpath.OCSP;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class OCSPStatusValidator implements CertificateValidator {

    private static Logger logger = LoggerFactory.getLogger(OCSPStatusValidator.class);

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

    public void validate(X509Certificate cert) throws CertificateValidationException {
        try {
            KeyStore ks = getDifiKeyStoreUtil().loadCaCertsKeystore();

            X509Certificate issuer = getCertsIssuerCertificate(ks, cert.getIssuerX500Principal());

            OCSP.RevocationStatus status = getRevocationStatus(cert, issuer);

            if (!status.getCertStatus().equals(OCSP.RevocationStatus.CertStatus.GOOD))
                throw new FailedValidationException("Certificate status is not reported as GOOD by OCSP.");
        } catch (CertificateValidationException e) {
            throw e;
        } catch (Exception e) {
            logger.debug(e.getMessage());
            throw new FailedValidationException(e.getMessage(), e);
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
}
