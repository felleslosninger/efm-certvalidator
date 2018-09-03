package no.difi.certvalidator.structure;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.rule.DummyRule;
import org.testng.Assert;
import org.testng.annotations.Test;

public class JunctionTest {

    @Test
    public void simpleAnd() throws Exception {
        Junction.and(DummyRule.alwaysSuccess(), DummyRule.alwaysSuccess(), DummyRule.alwaysSuccess())
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    public void simpleOr() throws Exception {
        Junction.or(new DummyRule(), new DummyRule("FAIL!"))
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        Junction.or(DummyRule.alwaysFail("FAIL!"), DummyRule.alwaysSuccess())
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        try {
            Junction.or(DummyRule.alwaysFail("FAIL!"), DummyRule.alwaysFail("FAIL!"))
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
    public void simpleOneTest() {
        Assert.assertTrue(Junction.and(new DummyRule()) instanceof DummyRule);
        Assert.assertTrue(Junction.and(new DummyRule(), new DummyRule()) instanceof AndJunction);

        Assert.assertTrue(Junction.or(new DummyRule()) instanceof DummyRule);
        Assert.assertTrue(Junction.or(new DummyRule(), new DummyRule()) instanceof OrJunction);

        Assert.assertTrue(Junction.xor(new DummyRule()) instanceof DummyRule);
        Assert.assertTrue(Junction.xor(new DummyRule(), new DummyRule()) instanceof XorJunction);
    }
}
