package no.difi.certvalidator.rule;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.ValidatorBuilder;
import no.difi.certvalidator.api.CrlCache;
import no.difi.certvalidator.util.SimpleCrlCache;
import org.junit.Assert;
import org.testng.annotations.Test;

import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

public class CRLRuleTest {

    private CrlCache crlCache = new SimpleCrlCache();

    @Test
    public void simple() throws Exception {
        ValidatorBuilder.newInstance()
                .addRule(new CRLRule(crlCache))
                .build()
                .validate((getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test(enabled = false)
    public void updateCrl() throws Exception {
        String crlUrl = "http://pilotonsitecrl.verisign.com/DigitaliseringsstyrelsenPilotOpenPEPPOLACCESSPOINTCA/LatestCRL.crl";

        crlCache.set(crlUrl, (X509CRL) CertificateFactory.getInstance("X509").generateCRL(getClass().getResourceAsStream("/peppol-test-ap.crl")));

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
