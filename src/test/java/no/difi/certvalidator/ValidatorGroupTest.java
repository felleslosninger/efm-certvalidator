package no.difi.certvalidator;

import com.google.common.io.ByteStreams;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;

public class ValidatorGroupTest {

    @Test
    public void simple() throws Exception {
        ValidatorGroup validator = ValidatorLoader.newInstance()
                .build(getClass().getResourceAsStream("/recipe-selfsigned.xml"));

        byte[] cert = ByteStreams.toByteArray(getClass().getResourceAsStream("/selfsigned.cer"));

        Assert.assertTrue(validator.isValid("default", cert));
        Assert.assertFalse(validator.isValid("default", new byte[]{}));

        Assert.assertTrue(validator.isValid("default", new ByteArrayInputStream(cert)));
        Assert.assertFalse(validator.isValid("default", new ByteArrayInputStream(new byte[]{})));

        validator.validate("default", cert);
        validator.validate("default", new ByteArrayInputStream(cert));
    }
}
