package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.apache.commons.io.IOUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class ValidatorHelperTest {

    @Test
    public void simpleTrue() {
        ValidatorHelper validatorHelper = ValidatorBuilder.newInstance().append(new DummyValidator()).build();
        Assert.assertTrue(validatorHelper.isValid(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    public void simpleFalse() {
        ValidatorHelper validatorHelper = new ValidatorHelper(new DummyValidator("FAIL!"));
        Assert.assertFalse(validatorHelper.isValid(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
        Assert.assertFalse(validatorHelper.isValid((InputStream) null));
    }

    @Test
    public void simpleByteArray() throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IOUtils.copy(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"), byteArrayOutputStream);

        ValidatorHelper validatorHelper = new ValidatorHelper(new DummyValidator("FAIL!"));
        Assert.assertFalse(validatorHelper.isValid(byteArrayOutputStream.toByteArray()));
        Assert.assertFalse(validatorHelper.isValid(new byte[] {}));

        try {
            validatorHelper.validate(byteArrayOutputStream.toByteArray());
            Assert.fail("Exception expected.");
        } catch (FailedValidationException e) {
            // Expected
        }

        validatorHelper = new ValidatorHelper(new DummyValidator());
        validatorHelper.validate(byteArrayOutputStream.toByteArray());
    }
}
