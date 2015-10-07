package no.difi.virksomhetssertifikat.rule;

import no.difi.virksomhetssertifikat.Validator;
import no.difi.virksomhetssertifikat.ValidatorBuilder;
import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.util.KeyStoreCertificateBucket;
import org.testng.Assert;
import org.testng.annotations.Test;

public class ChainRuleTest {

    @Test
    public void simple() throws Exception {
        KeyStoreCertificateBucket keyStoreCertificateBucket = new KeyStoreCertificateBucket("JKS", getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        CertificateBucket rootCertificates = keyStoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keyStoreCertificateBucket.toSimple("peppol-ap", "peppol-smp");

        Validator validator = ValidatorBuilder.newInstance()
                .addRule(new ChainRule(rootCertificates, intermediateCertificates))
                .build();

        validator.validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
        validator.validate(getClass().getResourceAsStream("/peppol-test-smp-difi.cer"));

        try {
            validator.validate(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer"));
            Assert.fail("Exception expected.");
        } catch (FailedValidationException e) {
            // No action.
        }
    }

}
