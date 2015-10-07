package no.difi.virksomhetssertifikat.structure;

import no.difi.virksomhetssertifikat.Validator;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.rule.DummyRule;
import org.testng.Assert;
import org.testng.annotations.Test;

public class JunctionTest {

    @Test
    public void simpleAnd() throws Exception {
        Junction.and(new DummyRule(), new DummyRule(), new DummyRule())
        .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    public void simpleOr() throws Exception {
        Junction.or(new DummyRule(), new DummyRule("FAIL!"))
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        Junction.or(new DummyRule("FAIL!"), new DummyRule())
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        try {
            Junction.or(new DummyRule("FAIL!"), new DummyRule("FAIL!"))
                    .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
            Assert.fail("Expected exception");
        } catch (FailedValidationException e) {
            // Expected
        }
    }

    @Test
    public void simpleXor() throws Exception {
        Junction.xor(new DummyRule(), new DummyRule("FAIL!"))
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        try {
            Junction.xor(new DummyRule(), new DummyRule())
                    .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
            Assert.fail("Expected exception");
        } catch (FailedValidationException e) {
            // Expected
        }

        try {
            Junction.xor(new DummyRule("FAIL"), new DummyRule("FAIL"))
                    .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
            Assert.fail("Expected exception");
        } catch (FailedValidationException e) {
            // Expected
        }
    }

    @Test
    public void simpleConstructor() {
        new Junction();
    }
}
