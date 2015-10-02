package no.difi.virksomhetssertifikat.usage;

import no.difi.virksomhetssertifikat.*;
import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.util.SimpleCertificateBucket;
import no.difi.virksomhetssertifikat.util.SimplePrincipalNameProvider;
import org.junit.Test;

public class PeppolTest {

    @Test
    public void simpleAp() throws Exception {
        CertificateBucket certificateBucket = new SimpleCertificateBucket(
                ValidatorHelper.getCertificate(getClass().getResourceAsStream("/peppol-test-ap.cer"))
        );

        ValidatorBuilder.newInstance()
                .append(new ExpirationValidator())
                .append(new PrincipalNameValidator("CN", new SimplePrincipalNameProvider("PEPPOL ACCESS POINT TEST CA"), PrincipalNameValidator.Principal.ISSUER))
                // TODO Chain
                // .append(new OCSPValidator(certificateBucket))
                .build()
                .validate(getClass().getResourceAsStream("/peppol-test-ap-difi.cer"));
    }

}
