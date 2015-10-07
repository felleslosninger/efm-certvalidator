package no.difi.virksomhetssertifikat;


import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.testng.annotations.Test;

public class SelfSignedRuleTest {

    @Test
    public void publiclySignedExpectedWithPubliclySigned() throws Exception {
        new SelfSignedRule()
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void selfSignedExpectedWithPubliclySigned() throws Exception {
        new SelfSignedRule(SelfSignedRule.Kind.SELF_SIGNED_ONLY)
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    public void bothExpectedWithPubliclySigned() throws Exception {
        new SelfSignedRule(SelfSignedRule.Kind.BOTH)
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void publiclySignedExpectedWithSelfSigned() throws Exception {
        new SelfSignedRule()
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }

    @Test
    public void selfSignedExpectedWithSelfSigned() throws Exception {
        new SelfSignedRule(SelfSignedRule.Kind.SELF_SIGNED_ONLY)
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }

    @Test
    public void bothExpectedWithSelfSigned() throws Exception {
        new SelfSignedRule(SelfSignedRule.Kind.BOTH)
                .validate(Validator.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }
}
