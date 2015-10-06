package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CrlCache;
import no.difi.virksomhetssertifikat.util.SimpleCrlCache;
import org.junit.Assert;
import org.testng.annotations.Test;

public class CRLValidatorTest {

    @Test
    public void simple() throws Exception {
        ValidatorBuilder.newInstance()
                .append(new CRLValidator())
                .build()
                .validate((getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    public void updateCrl() throws Exception {
        String crlUrl = "http://pilotonsitecrl.verisign.com/DigitaliseringsstyrelsenPilotOpenPEPPOLACCESSPOINTCA/LatestCRL.crl";

        CrlCache crlCache = new SimpleCrlCache();
        crlCache.set(crlUrl, CRLValidator.load(getClass().getResourceAsStream("/peppol-test-ap.crl")));

        Assert.assertTrue(crlCache.get(crlUrl).getNextUpdate().getTime() < System.currentTimeMillis());

        ValidatorBuilder.newInstance()
                .append(new CRLValidator(crlCache))
                .build()
                .validate((getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));

        Assert.assertTrue(crlCache.get(crlUrl).getNextUpdate().getTime() > System.currentTimeMillis());
    }

}
