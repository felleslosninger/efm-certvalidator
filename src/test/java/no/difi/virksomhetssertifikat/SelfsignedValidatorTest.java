package no.difi.virksomhetssertifikat;


import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.testng.annotations.Test;

public class SelfsignedValidatorTest {

    @Test
    public void publiclySignedExpectedWithPubliclySigned() throws Exception {
        new SelfsignedValidator()
                .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void selfSignedExpectedWithPubliclySigned() throws Exception {
        new SelfsignedValidator(SelfsignedValidator.Kind.SELF_SIGNED_ONLY)
                .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test
    public void bothExpectedWithPubliclySigned() throws Exception {
        new SelfsignedValidator(SelfsignedValidator.Kind.BOTH)
                .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void publiclySignedExpectedWithSelfSigned() throws Exception {
        new SelfsignedValidator()
                .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }

    @Test
    public void selfSignedExpectedWithSelfSigned() throws Exception {
        new SelfsignedValidator(SelfsignedValidator.Kind.SELF_SIGNED_ONLY)
                .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }

    @Test
    public void bothExpectedWithSelfSigned() throws Exception {
        new SelfsignedValidator(SelfsignedValidator.Kind.BOTH)
                .validate(ValidatorHelper.getCertificate(getClass().getResourceAsStream("/selfsigned.cer")));
    }
}
