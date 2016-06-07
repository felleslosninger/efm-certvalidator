package no.difi.certvalidator.rule;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.FailedValidationException;
import org.testng.annotations.Test;

public class CriticalExtensionRecognizedRuleTest {

    @Test(expectedExceptions = FailedValidationException.class)
    public void certificateHasOidsNotRecognized() throws Exception {
        Validator validator = new Validator(new CriticalExtensionRecognizedRule("12.0"));
        validator.validate(getClass().getResourceAsStream("/difi-move-test.cer"));
    }

}
