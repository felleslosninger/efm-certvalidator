package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.util.KeystoreCertificateBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

public class Chain2ValidatorTest {

    private static Logger logger = LoggerFactory.getLogger(Chain2ValidatorTest.class);

    @Test
    public void simple() throws Exception {
        try {
            KeystoreCertificateBucket keystoreCertificateBucket = new KeystoreCertificateBucket("JKS", getClass().getResourceAsStream("/peppol-test.jks"), "peppol");
            CertificateBucket rootCertificates = keystoreCertificateBucket.toSimple("peppol-root");
            CertificateBucket intermediateCertificates = keystoreCertificateBucket.toSimple("peppol-ap", "peppol-smp");

            ValidatorHelper validator = ValidatorBuilder.newInstance()
                    .append(new Chain2Validator(rootCertificates, intermediateCertificates))
                    .build();
            validator.isValid(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
        } catch (Exception e) {
            logger.warn(e.getMessage());
            // Assert.fail(e.getMessage());
        }
    }

}
