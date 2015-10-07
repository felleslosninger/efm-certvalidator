package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.testutil.X509TestGenerator;
import org.joda.time.DateTime;
import org.testng.Assert;
import org.testng.annotations.Test;

public class ExpirationSoonRuleTest extends X509TestGenerator {

    @Test
    public void simple() throws Exception {
        Validator validatorHelper = new Validator(new ExpirationSoonRule(5 * 24 * 60 * 60 * 1000));

        Assert.assertTrue(validatorHelper.isValid(createX509Certificate(DateTime.now().plusDays(1).toDate(), DateTime.now().plusDays(10).toDate())));
        Assert.assertTrue(validatorHelper.isValid(createX509Certificate(DateTime.now().plusDays(1).toDate(), DateTime.now().plusDays(6).toDate())));
        Assert.assertTrue(validatorHelper.isValid(createX509Certificate(DateTime.now().plusDays(1).toDate(), DateTime.now().plusDays(5).plusMinutes(1).toDate())));
        Assert.assertFalse(validatorHelper.isValid(createX509Certificate(DateTime.now().plusDays(1).toDate(), DateTime.now().plusDays(5).minusMinutes(1).toDate())));
        Assert.assertFalse(validatorHelper.isValid(createX509Certificate(DateTime.now().plusDays(1).toDate(), DateTime.now().plusDays(4).toDate())));
    }

}
