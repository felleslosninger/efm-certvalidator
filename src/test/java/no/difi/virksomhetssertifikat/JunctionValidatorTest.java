package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.testng.Assert;
import org.testng.annotations.Test;

public class JunctionValidatorTest {

    @Test
    public void simpleAnd() throws Exception {
        new JunctionValidator(JunctionValidator.Kind.AND,
                new DummyValidator(), new DummyValidator(), new DummyValidator())
        .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    public void simpleOr() throws Exception {
        new JunctionValidator(JunctionValidator.Kind.OR,
                new DummyValidator(), new DummyValidator("FAIL!"))
                .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        new JunctionValidator(JunctionValidator.Kind.OR,
                new DummyValidator("FAIL!"), new DummyValidator())
                .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        try {
            new JunctionValidator(JunctionValidator.Kind.OR,
                    new DummyValidator("FAIL!"), new DummyValidator("FAIL!"))
                    .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
            Assert.fail("Expected exception");
        } catch (FailedValidationException e) {
            // Expected
        }
    }

    @Test
    public void simpleXor() throws Exception {
        new JunctionValidator(JunctionValidator.Kind.XOR,
                new DummyValidator(), new DummyValidator("FAIL!"))
                .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        try {
            new JunctionValidator(JunctionValidator.Kind.XOR,
                    new DummyValidator(), new DummyValidator())
                    .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
            Assert.fail("Expected exception");
        } catch (FailedValidationException e) {
            // Expected
        }

        try {
            new JunctionValidator(JunctionValidator.Kind.XOR,
                    new DummyValidator("FAIL"), new DummyValidator("FAIL"))
                    .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
            Assert.fail("Expected exception");
        } catch (FailedValidationException e) {
            // Expected
        }
    }
}
