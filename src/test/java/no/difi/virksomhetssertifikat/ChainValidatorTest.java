package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.util.KeystoreCertificateBucket;
import org.testng.Assert;
import org.testng.annotations.Test;

public class ChainValidatorTest {

    @Test
    public void simple() throws Exception {
        KeystoreCertificateBucket keystoreCertificateBucket = new KeystoreCertificateBucket("JKS", getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
        CertificateBucket rootCertificates = keystoreCertificateBucket.toSimple("peppol-root");
        CertificateBucket intermediateCertificates = keystoreCertificateBucket.toSimple("peppol-ap", "peppol-smp");

        ValidatorHelper validator = ValidatorBuilder.newInstance()
                .append(new ChainValidator(rootCertificates, intermediateCertificates))
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
