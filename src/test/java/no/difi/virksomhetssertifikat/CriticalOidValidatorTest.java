package no.difi.virksomhetssertifikat;


import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.testutil.X509ExtensionCustom;
import no.difi.virksomhetssertifikat.testutil.X509TestGenerator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

public class CriticalOidValidatorTest extends X509TestGenerator {
    @Test
    public void shouldValidateCertWithOutAnyCriticalExtentions() throws Exception {
        CriticalOidValidator validator = new CriticalOidValidator("2");
        X509Certificate cert = createX509Certificate();
        validator.validate(cert);
    }

    @Test
    public void shouldValidateCertWithApprovedCriticalExtentions() throws Exception {
        CriticalOidValidator validator = new CriticalOidValidator("2.10.2");
        X509Certificate cert = createX509Certificate(new X509ExtensionCustom() {
            public void setup(X509v3CertificateBuilder v3CertGen) throws CertIOException {
                v3CertGen.addExtension(new ASN1ObjectIdentifier("2.10.2"), true, new byte[3]);
            }

        });
        validator.validate(cert);
    }


    @Test(expectedExceptions = FailedValidationException.class)
    public void shouldInvalidateCertWithACriticalExtentionsThatIsNotApproved() throws Exception {
        String approvedExtentionList = "2.10.2";
        CriticalOidValidator validator = new CriticalOidValidator(approvedExtentionList);
        X509Certificate cert = createX509Certificate(new X509ExtensionCustom() {
            public void setup(X509v3CertificateBuilder v3CertGen) throws CertIOException {
                String notApprovedExtention = "2.10.6";
                boolean CRITICAL = true;
                v3CertGen.addExtension(new ASN1ObjectIdentifier(notApprovedExtention), CRITICAL, new byte[3]);
            }
        });
        validator.validate(cert);
    }
}
