package no.difi.certvalidator.rule;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.util.SimpleCertificateBucket;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.InputStream;
import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public class WhitelistRuleTest {

    @Test
    public void simple() throws Exception {
        X509Certificate certificate;

        try (InputStream inputStream = getClass().getResourceAsStream("/selfsigned.cer")) {
            certificate = Validator.getCertificate(inputStream);
        }

        Assert.assertTrue(new Validator(new WhitelistRule(SimpleCertificateBucket.with(certificate))).isValid(certificate));
        Assert.assertFalse(new Validator(new WhitelistRule(SimpleCertificateBucket.with())).isValid(certificate));
    }

}
