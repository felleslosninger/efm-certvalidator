package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.api.PrincipalNameProvider;
import no.difi.virksomhetssertifikat.util.SimplePrincipalNameProvider;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.security.cert.CertificateEncodingException;

public class PrincipalNameValidatorTest {

    @Test
    public void onlyNoAllowed() throws Exception {
        ValidatorBuilder.newInstance()
                .append(new PrincipalNameValidator("C", new SimplePrincipalNameProvider("NO")))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void onlyDkAllowed() throws Exception {
        ValidatorBuilder.newInstance()
                .append(new PrincipalNameValidator("C", new SimplePrincipalNameProvider("DK")))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void fullName() throws Exception {
        ValidatorBuilder.newInstance()
                .append(new PrincipalNameValidator(new PrincipalNameProvider() {
                    @Override
                    public boolean validate(String value) {
                        return value.contains("NORWAY");
                    }
                }, PrincipalNameValidator.Principal.SUBJECT))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void triggerCertificateEncodingException() throws Exception {
        PrincipalNameProvider provider = Mockito.mock(PrincipalNameProvider.class);
        Mockito.doThrow(CertificateEncodingException.class).when(provider).validate(Mockito.anyString());

        ValidatorBuilder.newInstance()
                .append(new PrincipalNameValidator(provider))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }
}
