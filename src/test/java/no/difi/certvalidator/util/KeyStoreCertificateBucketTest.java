package no.difi.certvalidator.util;

import com.google.common.collect.Lists;
import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.CertificateBucketException;
import org.testng.Assert;
import org.testng.annotations.Test;

public class KeyStoreCertificateBucketTest {

    @Test
    public void simple() throws Exception {
        KeyStoreCertificateBucket certificateBucket = new KeyStoreCertificateBucket(getClass().getResourceAsStream("/peppol-test.jks"), "peppol");

        Assert.assertNotNull(certificateBucket.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")).getIssuerX500Principal()));
        Assert.assertNotNull(certificateBucket.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer")).getIssuerX500Principal()));
        Assert.assertNull(certificateBucket.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer")).getIssuerX500Principal()));
        Assert.assertNull(certificateBucket.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer")).getIssuerX500Principal()));
    }

    @Test
    public void startsWithTest() throws Exception {
        KeyStoreCertificateBucket certificateBucket = new KeyStoreCertificateBucket(getClass().getResourceAsStream("/peppol-test.jks"), "peppol");

        Assert.assertEquals(Lists.newArrayList(certificateBucket.startsWith("PEPPOL-", "peppol-").iterator()).size(), 4);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void triggerNullPointerInIterator() throws Exception {
        new KeyStoreCertificateBucket(null).iterator();
    }

    @Test(expectedExceptions = CertificateBucketException.class)
    public void triggerNullPointerInToSimple() throws Exception {
        new KeyStoreCertificateBucket(null).toSimple();
    }

    @Test(expectedExceptions = CertificateBucketException.class)
    public void triggerNullPointerInConstructor() throws Exception {
        new KeyStoreCertificateBucket(null, "password");
    }

    @Test(expectedExceptions = CertificateBucketException.class)
    @SuppressWarnings("all")
    public void triggerNullPointerInStartsWith() throws Exception {
        new KeyStoreCertificateBucket(null).startsWith(null);
    }
}
