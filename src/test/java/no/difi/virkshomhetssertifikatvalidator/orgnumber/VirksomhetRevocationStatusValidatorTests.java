package no.difi.virkshomhetssertifikatvalidator.orgnumber;

import no.difi.virksomhetssertifikat.DifiKeyStoreUtil;
import no.difi.virksomhetssertifikat.VirksomhetRevocationOCSPStatusValidator;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;
import sun.security.provider.certpath.OCSP;
import testutil.X509TestGenerator;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.Date;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class VirksomhetRevocationStatusValidatorTests extends X509TestGenerator {

    @Test
    public void shouldValidateACertificateIfItIsntRevoced() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, CertPathValidatorException, CertificateException, KeyStoreException, OperatorCreationException {
        X509Certificate cert = createX509Certificate();
        VirksomhetRevocationOCSPStatusValidator validator = getVirksomhetRevocationStatusValidatorStub(cert, OCSP.RevocationStatus.CertStatus.GOOD);

        Mockito.when(validator.getDifiKeyStoreUtil()).thenReturn(Mockito.mock(DifiKeyStoreUtil.class));

        assertTrue(validator.isValid(cert));

    }

    @Test
    public void shouldRejectACertificateIfItIsRevoced() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, CertPathValidatorException, CertificateException, OperatorCreationException {
        X509Certificate cert = createX509Certificate();
        VirksomhetRevocationOCSPStatusValidator validator = getVirksomhetRevocationStatusValidatorStub(cert, OCSP.RevocationStatus.CertStatus.REVOKED);

        assertFalse(validator.isValid(cert));
    }

    @Test
    public void shouldRejectACertificateIfTheStatusIsUnknown() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, CertPathValidatorException, CertificateException, OperatorCreationException {
        X509Certificate cert = createX509Certificate();
        VirksomhetRevocationOCSPStatusValidator validator = getVirksomhetRevocationStatusValidatorStub(cert, OCSP.RevocationStatus.CertStatus.UNKNOWN);

        assertFalse(validator.isValid(cert));
    }

    @Test
    public void shouldRejectACertificateIfTheCheckTimesOut() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, CertPathValidatorException, CertificateException, OperatorCreationException {
        X509Certificate cert = createX509Certificate();
        VirksomhetRevocationOCSPStatusValidator validator1 = Mockito.mock(VirksomhetRevocationOCSPStatusValidator.class);
        Mockito.when(validator1.isValid(Matchers.any(X509Certificate.class))).thenCallRealMethod();
        Mockito.when(validator1.getRevocationStatus(Matchers.eq(cert), Matchers.any(X509Certificate.class))).thenThrow(new IOException("test case"));
        VirksomhetRevocationOCSPStatusValidator validator = validator1;

        assertFalse(validator.isValid(cert));
    }

    private VirksomhetRevocationOCSPStatusValidator getVirksomhetRevocationStatusValidatorStub(X509Certificate cert, final OCSP.RevocationStatus.CertStatus status) throws IOException, CertPathValidatorException {
        VirksomhetRevocationOCSPStatusValidator validator = Mockito.mock(VirksomhetRevocationOCSPStatusValidator.class);
        Mockito.when(validator.isValid(Matchers.any(X509Certificate.class))).thenCallRealMethod();
        Mockito.when(validator.getRevocationStatus(Matchers.eq(cert), Matchers.any(X509Certificate.class))).thenReturn(new OCSP.RevocationStatus() {
            @Override
            public CertStatus getCertStatus() {

                return status;
            }

            @Override
            public Date getRevocationTime() {
                return new Date();
            }

            @Override
            public CRLReason getRevocationReason() {
                return null;
            }

            @Override
            public Map<String, Extension> getSingleExtensions() {
                return null;
            }
        });

        Mockito.when(validator.getDifiKeyStoreUtil()).thenReturn(createKeyStoreUtil());
        return validator;
    }

    private DifiKeyStoreUtil createKeyStoreUtil() {
        return new DifiKeyStoreUtil(getClass().getResourceAsStream("classpath:/config/cacserts.jks"), "changeit", "JKS", getClass().getResourceAsStream("classpath:/config/intermediate.jks"), "changeit", "JKS");
    }
}
