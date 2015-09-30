package no.difi.virksomhetssertifikat;


import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;
import no.difi.virksomhetssertifikat.testutil.X509TestGenerator;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;

public class ChainValidatorTests extends X509TestGenerator {

    @Test(expected = CertificateValidationException.class)
    public void shouldRejectACertificateThatIsntSigned() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, KeyStoreException, IOException, OperatorCreationException, CertificateValidationException {
        X509Certificate issuer = createX509Certificate();

        ChainValidator validator = Mockito.mock(ChainValidator.class);
        Mockito.when(validator.getTrustAnchors(Matchers.any(KeyStore.class))).thenReturn(new HashSet<TrustAnchor>(Arrays.asList(new TrustAnchor(issuer, null))));

        X509Certificate cert = createX509Certificate();
        Mockito.when(validator.isValid(cert)).thenCallRealMethod();

        validator.isValid(cert);
    }
}
