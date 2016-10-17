package no.difi.certvalidator;

import com.google.common.io.ByteStreams;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.rule.DummyRule;
import no.difi.certvalidator.util.SimpleCachingCrlFetcher;
import no.difi.certvalidator.util.SimpleCrlCache;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.File;

public class ValidatorLoaderTest {

    @Test
    public void simplePeppolTest() throws Exception {
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

    @Test
    public void simpleVirksertTest() throws Exception {
        Validator validator = ValidatorLoader.newInstance()
                .put("crlFetcher", new SimpleCachingCrlFetcher(new SimpleCrlCache()))
                .build(getClass().getResourceAsStream("/receipt-virksert-test.xml"));

        Assert.assertTrue(validator.isValid(getClass().getResourceAsStream("/virksert-test-difi.cer")));
        Assert.assertFalse(validator.isValid(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer")));
    }

    @Test
    public void simpleVirksertTestAlternative() throws Exception {
        Validator validator = ValidatorLoader.newInstance()
                .put("crlFetcher", new SimpleCachingCrlFetcher(new SimpleCrlCache()))
                .build(getClass().getResourceAsStream("/receipt-virksert-test-alt.xml"));

        Assert.assertTrue(validator.isValid(getClass().getResourceAsStream("/virksert-test-difi.cer")));
        Assert.assertFalse(validator.isValid(getClass().getResourceAsStream("/peppol-prod-ap-difi.cer")));
    }

    @Test
    public void simpleSelfSigned() throws Exception {
        Validator validator = ValidatorLoader.newInstance()
                .build(getClass().getResourceAsStream("/receipt-selfsigned.xml"));

        Assert.assertTrue(validator.isValid(getClass().getResourceAsStream("/selfsigned.cer")));
        Assert.assertFalse(validator.isValid(getClass().getResourceAsStream("/virksert-test-difi.cer")));
    }

    @Test(expectedExceptions = ValidatorParsingException.class)
    public void triggerParserException() throws Exception {
        ValidatorLoader.newInstance()
                .build(new ByteArrayInputStream(
                        ("<ValidatorReceipt xmlns=\"http://difi.no/xsd/certvalidator/1.0\">" +
                                "<Validator><Class>no.clazz.Here</Class></Validator>" +
                                "</ValidatorReceipt>").getBytes()));
    }

    @Test(expectedExceptions = ValidatorParsingException.class)
    public void triggerReferenceNotFound() throws Exception {
        ValidatorLoader.newInstance()
                .build(new ByteArrayInputStream(
                        ("<ValidatorReceipt xmlns=\"http://difi.no/xsd/certvalidator/1.0\">" +
                                "<Validator><RuleReference>reference</RuleReference></Validator>" +
                                "</ValidatorReceipt>").getBytes()));
    }

    @Test
    public void triggerReferenceFound() throws Exception {
        ValidatorLoader.newInstance()
                .put("reference", new DummyRule())
                .build(new ByteArrayInputStream(
                        ("<ValidatorReceipt xmlns=\"http://difi.no/xsd/certvalidator/1.0\">" +
                                "<Validator><RuleReference>reference</RuleReference></Validator>" +
                                "</ValidatorReceipt>").getBytes()));
    }

    @Test(expectedExceptions = ValidatorParsingException.class)
    public void triggerValidatorReferenceNotFound() throws Exception {
        ValidatorLoader.newInstance()
                .build(new ByteArrayInputStream(
                        ("<ValidatorReceipt xmlns=\"http://difi.no/xsd/certvalidator/1.0\">" +
                                "<Validator><ValidatorReference>reference</ValidatorReference></Validator>" +
                                "</ValidatorReceipt>").getBytes()));
    }

    @Test
    public void triggerValidatorReferenceFound() throws Exception {
        ValidatorLoader.newInstance()
                .put("#validator::reference", new DummyRule())
                .build(new ByteArrayInputStream(
                        ("<ValidatorReceipt xmlns=\"http://difi.no/xsd/certvalidator/1.0\">" +
                                "<Validator><ValidatorReference>reference</ValidatorReference></Validator>" +
                                "</ValidatorReceipt>").getBytes()));
    }

    @Test
    public void triggerJunctionOr() throws Exception {
        ValidatorLoader.newInstance()
                .build(new ByteArrayInputStream(
                        ("<ValidatorReceipt xmlns=\"http://difi.no/xsd/certvalidator/1.0\">" +
                                "<Validator><Junction type=\"OR\"><Dummy/></Junction></Validator>" +
                                "</ValidatorReceipt>").getBytes()));
    }

    @Test
    public void triggerJunctionXor() throws Exception {
        ValidatorLoader.newInstance()
                .build(new ByteArrayInputStream(
                        ("<ValidatorReceipt xmlns=\"http://difi.no/xsd/certvalidator/1.0\">" +
                                "<Validator><Junction type=\"XOR\"><Dummy/></Junction></Validator>" +
                                "</ValidatorReceipt>").getBytes()));
    }

    @Test
    public void simpleConstructorTest() {
        new ValidatorLoaderParser();
    }
}
