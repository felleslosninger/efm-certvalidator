package no.difi.certvalidator;

import no.difi.certvalidator.util.SimpleCachingCrlFetcher;
import no.difi.certvalidator.util.SimpleCrlCache;
import org.testng.Assert;
import org.testng.annotations.Test;

public class ValidatorLoaderTest {

    @Test
    public void simple() throws Exception {
        ValidatorGroup validator = ValidatorLoader.newInstance()
                .put("crlCache", new SimpleCrlCache())
                .build(getClass().getResourceAsStream("/receipt-peppol-test.xml"));

        Assert.assertEquals(validator.getName(), "peppol-test");
        Assert.assertNotNull(validator.getVersion());

        Assert.assertTrue(validator.isValid(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
        Assert.assertTrue(validator.isValid("AP", getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
        Assert.assertFalse(validator.isValid("SMP", getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        // Assert.assertTrue(validator.isValid(getClass().getResourceAsStream("/peppol-test-smp-difi.cer")));

        Assert.assertFalse(validator.isValid(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer")));
        Assert.assertFalse(validator.isValid(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer")));
    }
}
