package no.difi.virksomhetssertifikat.usage;

import no.difi.virksomhetssertifikat.*;
import no.difi.virksomhetssertifikat.util.SimplePrincipalNameProvider;
import org.junit.Test;

public class PeppolTest {

    @Test
    public void simpleAp() throws Exception {
        ValidatorBuilder.newInstance()
                .append(new ExpirationValidator())
                .append(new PrincipalNameValidator("CN", new SimplePrincipalNameProvider("PEPPOL ACCESS POINT TEST CA"), PrincipalNameValidator.Principal.ISSUER))
                // TODO Chain
                // TODO OCSP
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-ap.cer"));
    }

}
