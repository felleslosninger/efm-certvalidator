package no.difi.certvalidator.rule;


import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.testutil.X509ExtensionCustom;
import no.difi.certvalidator.testutil.X509TestGenerator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

public class CriticalOidRuleTest extends X509TestGenerator {
    @Test(enabled = false)
    public void shouldValidateCertWithOutAnyCriticalExtentions() throws Exception {
        CriticalOidRule validator = new CriticalOidRule("2");
        X509Certificate cert = createX509Certificate();
        validator.validate(cert);
    }

    @Test
    public void shouldValidateCertWithApprovedCriticalExtentions() throws Exception {
        CriticalOidRule validator = new CriticalOidRule("2.10.2");
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
        CriticalOidRule validator = new CriticalOidRule(approvedExtentionList);
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
