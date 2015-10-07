package no.difi.virksomhetssertifikat.rule;


import no.difi.virksomhetssertifikat.Validator;
import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.testng.annotations.Test;

public class SigningRuleTest {

    @Test
    public void publiclySignedExpectedWithPubliclySigned() throws Exception {
        SigningRule.PublicSignedOnly()
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void selfSignedExpectedWithPubliclySigned() throws Exception {
        SigningRule.SelfSignedOnly()
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void publiclySignedExpectedWithSelfSigned() throws Exception {
        SigningRule.PublicSignedOnly()
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }

    @Test
    public void selfSignedExpectedWithSelfSigned() throws Exception {
        SigningRule.SelfSignedOnly()
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }

    @Test(expectedExceptions = CertificateValidationException.class)
    public void triggerException() throws Exception {
        SigningRule.PublicSignedOnly().validate(null);
    }
}
