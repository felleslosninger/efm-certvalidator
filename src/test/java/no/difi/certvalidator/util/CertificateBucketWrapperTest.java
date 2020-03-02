package no.difi.certvalidator.util;

import no.difi.certvalidator.rule.ChainRule;
import no.difi.certvalidator.ValidatorBuilder;
import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.CertificateBucket;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Test exists to show potential use.
 */
public class CertificateBucketWrapperTest {

    @Test(enabled = false)
    public void simple() throws Exception {
        // Load keystore
        KeyStoreCertificateBucket keyStoreCertificateBucket = new KeyStoreCertificateBucket(getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        // Fetch root certificate from keystore
        CertificateBucket rootCertificates = keyStoreCertificateBucket.toSimple("peppol-root");
        // Define a wrapper for intermediate certificates, currently empty
        CertificateBucketWrapper intermediateCertificates = new CertificateBucketWrapper(null);

        // Build the validator
        Validator validator = ValidatorBuilder.newInstance()
                .addRule(new ChainRule(rootCertificates, intermediateCertificates))
                .build();

        // See, no certificates inside wrapper!
        Assert.assertNull(intermediateCertificates.getCertificateBucket());

        // Set intermediate certificate
        intermediateCertificates.setCertificateBucket(keyStoreCertificateBucket.toSimple("peppol-ap"));
        // Validate!
        validator.validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));

        try {
            // Currently not valid
            validator.validate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer"));
            Assert.fail("Exception expected!");
        } catch (Exception e) {
            // No action
        }

        // Change intermediate certificate
        intermediateCertificates.setCertificateBucket(keyStoreCertificateBucket.toSimple("peppol-smp"));
        // Validate!
        validator.validate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer"));

        try {
            // Currently not valid
            validator.validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
            Assert.fail("Exception expected!");
        } catch (Exception e) {
            // No action
        }

        // Add certificate to existing bucket inside wrapper
        keyStoreCertificateBucket.toSimple((SimpleCertificateBucket) intermediateCertificates.getCertificateBucket(), "peppol-ap");

        // Validate!
        validator.validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
        // Validate!
        validator.validate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer"));

        // Find issuer certificate
        Assert.assertNotNull(intermediateCertificates.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")).getIssuerX500Principal()));
        Assert.assertNotNull(intermediateCertificates.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer")).getIssuerX500Principal()));
        Assert.assertNull(intermediateCertificates.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer")).getIssuerX500Principal()));
        Assert.assertNull(intermediateCertificates.findBySubject(
                Validator.getCertificate(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer")).getIssuerX500Principal()));
    }

}
