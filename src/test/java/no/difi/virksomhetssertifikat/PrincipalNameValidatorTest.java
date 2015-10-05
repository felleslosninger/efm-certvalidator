package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.util.SimplePrincipalNameProvider;
import org.testng.annotations.Test;

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
}
