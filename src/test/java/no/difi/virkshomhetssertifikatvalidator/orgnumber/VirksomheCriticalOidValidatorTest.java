package no.difi.virkshomhetssertifikatvalidator.orgnumber;


import no.difi.virksomhetssertifikat.VirksomheCriticalOidValidator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.junit.Test;
import testutil.X509ExtensionCustom;
import testutil.X509TestGenerator;

import java.security.cert.X509Certificate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VirksomheCriticalOidValidatorTest extends X509TestGenerator {
    @Test
    public void shouldValidateCertWithOutAnyCriticalExtentions() throws Exception {
        VirksomheCriticalOidValidator validator = new VirksomheCriticalOidValidator("2");
        X509Certificate cert = createX509Certificate();
        assertTrue(validator.isValid(cert));
    }

    @Test
    public void shouldValidateCertWithApprovedCriticalExtentions() throws Exception {
        VirksomheCriticalOidValidator validator = new VirksomheCriticalOidValidator("2.10.2");
        X509Certificate cert = createX509Certificate(new X509ExtensionCustom() {
            public void setup(X509v3CertificateBuilder v3CertGen) throws CertIOException {
                v3CertGen.addExtension(new ASN1ObjectIdentifier("2.10.2"), true, new byte[3]);
            }

        });
        assertTrue(validator.isValid(cert));
    }


    @Test
    public void shouldInvalidateCertWithACriticalExtentionsThatIsNotApproved() throws Exception {
        String approvedExtentionList = "2.10.2";
        VirksomheCriticalOidValidator validator = new VirksomheCriticalOidValidator(approvedExtentionList);
        X509Certificate cert = createX509Certificate(new X509ExtensionCustom() {
            public void setup(X509v3CertificateBuilder v3CertGen) throws CertIOException {
                String notApprovedExtention = "2.10.6";
                boolean CRITICAL = true;
                v3CertGen.addExtension(new ASN1ObjectIdentifier(notApprovedExtention), CRITICAL, new byte[3]);
            }
        });
        assertFalse(validator.isValid(cert));
    }
}
