package no.difi.virkshomhetssertifikatvalidator.orgnumber;

import no.difi.virksomhetssertifikat.VirksomhetExpirationDateValidator;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.DateTime;
import org.junit.Test;
import testutil.X509TestGenerator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;



public class VirksomhetExpirationDateValidatorTest extends X509TestGenerator {

    @Test
    public void shouldValidateAValidCertificate() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        VirksomhetExpirationDateValidator validator = new VirksomhetExpirationDateValidator();

        X509Certificate cert = createX509Certificate(DateTime.now().minusDays(10).toDate(), DateTime.now().plusDays(10).toDate());

        assertTrue(validator.isValid(cert));
    }

    @Test
    public void shouldInvalidateAExpiredCertificate() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        VirksomhetExpirationDateValidator validator = new VirksomhetExpirationDateValidator();

        X509Certificate cert = createX509Certificate(DateTime.now().minusDays(10).toDate(), DateTime.now().minusDays(2).toDate());

        assertFalse(validator.isValid(cert));
    }

    @Test
    public void shouldInvalidateANotNotbeforeCertificate() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        VirksomhetExpirationDateValidator validator = new VirksomhetExpirationDateValidator();

        X509Certificate cert = createX509Certificate(DateTime.now().plusDays(10).toDate(), DateTime.now().plusDays(20).toDate());

        assertFalse(validator.isValid(cert));
    }
}
