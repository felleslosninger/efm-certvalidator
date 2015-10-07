package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.testng.Assert;
import org.testng.annotations.Test;

public class JunctionRuleTest {

    @Test
    public void simpleAnd() throws Exception {
        new JunctionRule(JunctionRule.Kind.AND,
                new DummyRule(), new DummyRule(), new DummyRule())
        .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    public void simpleOr() throws Exception {
        new JunctionRule(JunctionRule.Kind.OR,
                new DummyRule(), new DummyRule("FAIL!"))
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        new JunctionRule(JunctionRule.Kind.OR,
                new DummyRule("FAIL!"), new DummyRule())
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        try {
            new JunctionRule(JunctionRule.Kind.OR,
                    new DummyRule("FAIL!"), new DummyRule("FAIL!"))
                    .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
            Assert.fail("Expected exception");
        } catch (FailedValidationException e) {
            // Expected
        }
    }

    @Test
    public void simpleXor() throws Exception {
        new JunctionRule(JunctionRule.Kind.XOR,
                new DummyRule(), new DummyRule("FAIL!"))
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        try {
            new JunctionRule(JunctionRule.Kind.XOR,
                    new DummyRule(), new DummyRule())
                    .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
            Assert.fail("Expected exception");
        } catch (FailedValidationException e) {
            // Expected
        }

        try {
            new JunctionRule(JunctionRule.Kind.XOR,
                    new DummyRule("FAIL"), new DummyRule("FAIL"))
                    .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
            Assert.fail("Expected exception");
        } catch (FailedValidationException e) {
            // Expected
        }
    }
}
