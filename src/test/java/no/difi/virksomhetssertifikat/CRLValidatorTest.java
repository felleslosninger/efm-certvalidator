package no.difi.virksomhetssertifikat;

import org.testng.annotations.Test;

public class CRLValidatorTest {

    @Test
    public void simple() throws Exception {
        ValidatorBuilder.newInstance()
                .append(new CRLValidator())
                .build()
                .validate((getClass().getResourceAsStream("/peppol-test-ap-difi.cer")));
    }

}
