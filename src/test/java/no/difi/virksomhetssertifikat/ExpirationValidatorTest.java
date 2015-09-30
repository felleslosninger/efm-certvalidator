package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.joda.time.DateTime;
import org.junit.Test;
import no.difi.virksomhetssertifikat.testutil.X509TestGenerator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;



public class ExpirationValidatorTest extends X509TestGenerator {

    @Test
    public void shouldValidateAValidCertificate() throws CertificateValidationException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        ExpirationValidator validator = new ExpirationValidator();

        X509Certificate cert = createX509Certificate(DateTime.now().minusDays(10).toDate(), DateTime.now().plusDays(10).toDate());

        assertTrue(validator.isValid(cert));
    }

    @Test(expected = FailedValidationException.class)
    public void shouldInvalidateAExpiredCertificate() throws CertificateValidationException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        ExpirationValidator validator = new ExpirationValidator();

        X509Certificate cert = createX509Certificate(DateTime.now().minusDays(10).toDate(), DateTime.now().minusDays(2).toDate());

        assertFalse(validator.isValid(cert));
    }

    @Test(expected = FailedValidationException.class)
    public void shouldInvalidateANotNotbeforeCertificate() throws CertificateValidationException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        ExpirationValidator validator = new ExpirationValidator();

        X509Certificate cert = createX509Certificate(DateTime.now().plusDays(10).toDate(), DateTime.now().plusDays(20).toDate());

        assertFalse(validator.isValid(cert));
    }
}
