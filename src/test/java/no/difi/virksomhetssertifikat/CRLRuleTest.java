package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CrlCache;
import no.difi.virksomhetssertifikat.util.SimpleCrlCache;
import org.junit.Assert;
import org.testng.annotations.Test;

public class CRLRuleTest {

    @Test
    public void simple() throws Exception {
        ValidatorBuilder.newInstance()
                .addRule(new CRLRule())
                .build()
                .validate((getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    public void updateCrl() throws Exception {
        String crlUrl = "http://pilotonsitecrl.verisign.com/DigitaliseringsstyrelsenPilotOpenPEPPOLACCESSPOINTCA/LatestCRL.crl";

        CrlCache crlCache = new SimpleCrlCache();
        crlCache.set(crlUrl, CRLRule.load(getClass().getResourceAsStream("/peppol-test-ap.crl")));

        Validator validatorHelper = ValidatorBuilder.newInstance()
                .addRule(new CRLRule(crlCache))
                .build();

        Assert.assertTrue(crlCache.get(crlUrl).getNextUpdate().getTime() < System.currentTimeMillis());

        validatorHelper.validate((getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        Assert.assertTrue(crlCache.get(crlUrl).getNextUpdate().getTime() > System.currentTimeMillis());

        crlCache.set(crlUrl, null);
        Assert.assertNull(crlCache.get(crlUrl));

        validatorHelper.validate((getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        Assert.assertNotNull(crlCache.get(crlUrl));
    }

}
