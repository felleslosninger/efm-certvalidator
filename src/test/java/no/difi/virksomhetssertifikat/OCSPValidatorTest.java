package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.testutil.X509TestGenerator;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

public class OCSPValidatorTest extends X509TestGenerator {

    @Test(enabled = false)
    public void simple() throws Exception {
        OCSPValidator ocspValidator = Mockito.mock(OCSPValidator.class);
        Mockito.doCallRealMethod().when(ocspValidator).validate(Matchers.any(X509Certificate.class));

        ocspValidator.validate(createX509Certificate());
    }

}
