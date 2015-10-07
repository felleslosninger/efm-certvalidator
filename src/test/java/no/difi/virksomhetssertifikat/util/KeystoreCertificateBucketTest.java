package no.difi.virksomhetssertifikat.util;

import no.difi.virksomhetssertifikat.Validator;
import no.difi.virksomhetssertifikat.api.CertificateBucketException;
import org.testng.Assert;
import org.testng.annotations.Test;

public class KeystoreCertificateBucketTest {

    @Test
    public void simple() throws Exception {
        KeystoreCertificateBucket certificateBucket = new KeystoreCertificateBucket(getClass().getResourceAsStream("/peppol-test.jks"), "peppol");

        Assert.assertNotNull(certificateBucket.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")).getIssuerX500Principal()));
        Assert.assertNotNull(certificateBucket.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer")).getIssuerX500Principal()));
        Assert.assertNull(certificateBucket.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer")).getIssuerX500Principal()));
        Assert.assertNull(certificateBucket.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer")).getIssuerX500Principal()));
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void triggerNullPointerInIterator() throws Exception {
        new KeystoreCertificateBucket(null).iterator();
    }

    @Test(expectedExceptions = CertificateBucketException.class)
    public void triggerNullPointerInToSimple() throws Exception {
        new KeystoreCertificateBucket(null).toSimple();
    }

    @Test(expectedExceptions = CertificateBucketException.class)
    public void triggerNullPointerInConstructor() throws Exception {
        new KeystoreCertificateBucket(null, "password");
    }
}
