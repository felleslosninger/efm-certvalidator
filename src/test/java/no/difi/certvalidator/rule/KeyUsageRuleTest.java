package no.difi.certvalidator.rule;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.util.KeyUsage;
import org.testng.annotations.Test;

/**
 * @author erlend
 */
public class KeyUsageRuleTest {

    @Test
    public void simpleValid() throws Exception {
        new Validator(
                new KeyUsageRule(KeyUsage.NON_REPUDIATION))
                .validate(getClass().getResourceAsStream("/virksert-test-difi.cer"));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void simpleFailed() throws Exception {
        new Validator(new KeyUsageRule())
                .validate(getClass().getResourceAsStream("/virksert-test-difi.cer"));
    }

    @Test
    public void simplePeppol() throws Exception {
        new Validator(new KeyUsageRule(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT,
                KeyUsage.DATA_ENCIPHERMENT, KeyUsage.KEY_AGREEMENT))
                .validate(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer"));
    }
}