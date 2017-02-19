package no.difi.certvalidator.util;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author erlend
 */
public class KeyUsageTest {

    @Test
    public void simple() {
        Assert.assertEquals(KeyUsage.of(5), KeyUsage.KEY_CERT_SIGN);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void simpleException() {
        KeyUsage.of(10);
    }
}
