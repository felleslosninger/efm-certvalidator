package no.difi.certvalidator;

import com.google.common.io.ByteStreams;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.util.SimpleCrlCache;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.File;

public class ValidatorLoaderTest {

    @Test
    public void simple() throws Exception {
        ValidatorGroup validator = ValidatorLoader.newInstance()
                .put("crlCache", new SimpleCrlCache())
                .build(new File(getClass().getResource("/receipt-peppol-test.xml").toURI()).toPath());

        Assert.assertEquals(validator.getName(), "peppol-test");
        Assert.assertNotNull(validator.getVersion());

        byte[] byteCert = ByteStreams.toByteArray(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
        Assert.assertTrue(validator.isValid(byteCert));
        validator.validate("AP", byteCert);
        validator.validate("AP", getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
        Assert.assertTrue(validator.isValid("AP", byteCert));
        Assert.assertFalse(validator.isValid("SMP", Validator.getCertificate(byteCert)));
        Assert.assertFalse(validator.isValid("Other!", byteCert));

        // Assert.assertTrue(validator.isValid(getClass().getResourceAsStream("/peppol-test-smp-difi.cer")));

        Assert.assertFalse(validator.isValid(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer")));
        Assert.assertFalse(validator.isValid("AP", getClass().getResourceAsStream("/peppol-prod-ap-difi.cer")));
        Assert.assertFalse(validator.isValid("AP", ByteStreams.toByteArray(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer"))));

        Assert.assertFalse(validator.isValid(getClass().getResourceAsStream("/peppol-prod-smp-difi.cer")));
        Assert.assertFalse(validator.isValid("SMP", getClass().getResourceAsStream("/peppol-prod-smp-difi.cer")));
    }

    @Test(expectedExceptions = ValidatorParsingException.class)
    public void triggerParserException() throws Exception {
        ValidatorLoader.newInstance()
                .build(new ByteArrayInputStream(
                        ("<ValidatorReceipt xmlns=\"http://difi.no/xsd/certvalidator/1.0\" name=\"peppol-test\" version=\"2016-10-16\">" +
                                "<Validator><Class>no.clazz.Here</Class></Validator>" +
                                "</ValidatorReceipt>").getBytes()));
    }

    @Test
    public void simpleConstructorTest() {
        new ValidatorLoaderParser();
    }
}
