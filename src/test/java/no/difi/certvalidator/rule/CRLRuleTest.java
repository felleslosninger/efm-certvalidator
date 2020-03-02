package no.difi.certvalidator.rule;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.ValidatorBuilder;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.CrlCache;
import no.difi.certvalidator.api.CrlFetcher;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.util.SimpleCrlCache;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;

public class CRLRuleTest {

    private CrlCache crlCache = new SimpleCrlCache();

    @Test(enabled = false)
    public void simple() throws Exception {
        ValidatorBuilder.newInstance()
                .addRule(new CRLRule())
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

    @Test(expectedExceptions = CertificateValidationException.class)
    public void noUrlsSet() throws Exception {
        Assert.assertEquals(CRLRule.getCrlDistributionPoints(Validator.getCertificate(getClass().getResourceAsStream("/nooids.cer"))).size(), 0);
    }

    @Test
    public void noUrlsInSet() throws Exception {
        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        Mockito.doReturn(Collections.emptySet()).when(certificate).getNonCriticalExtensionOIDs();

        Assert.assertEquals(CRLRule.getCrlDistributionPoints(certificate).size(), 0);
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void revoked() throws Exception {
        X509Certificate certificate = Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));

        X509CRL x509CRL = Mockito.mock(X509CRL.class);
        Mockito.doReturn(true).when(x509CRL).isRevoked(certificate);

        CrlCache crlCache = new SimpleCrlCache();
        crlCache.set("http://pilotonsitecrl.verisign.com/DigitaliseringsstyrelsenPilotOpenPEPPOLACCESSPOINTCA/LatestCRL.crl", x509CRL);

        CRLRule rule = new CRLRule(crlCache);
        rule.validate(certificate);
    }

    @Test
    public void crlIsNull() throws Exception {
        X509Certificate certificate = Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));

        CRLRule rule = new CRLRule(new CrlFetcher() {
            @Override
            public X509CRL get(String url) throws CertificateValidationException {
                return null;
            }
        });
        rule.validate(certificate);
    }
}
