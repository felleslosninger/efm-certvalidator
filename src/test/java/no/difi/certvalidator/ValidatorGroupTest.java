package no.difi.certvalidator;

import com.google.common.io.ByteStreams;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;

public class ValidatorGroupTest {

    @Test
    public void simple() throws Exception {
        ValidatorGroup validator = ValidatorLoader.newInstance()
                .build(getClass().getResourceAsStream("/receipt-selfsigned.xml"));

        byte[] cert = ByteStreams.toByteArray(getClass().getResourceAsStream("/selfsigned.cer"));

        Assert.assertTrue(validator.isValid(cert));
        Assert.assertFalse(validator.isValid(new byte[]{}));

        Assert.assertTrue(validator.isValid(new ByteArrayInputStream(cert)));
        Assert.assertFalse(validator.isValid(new ByteArrayInputStream(new byte[]{})));

        validator.validate(cert);
        validator.validate(new ByteArrayInputStream(cert));
    }
}
