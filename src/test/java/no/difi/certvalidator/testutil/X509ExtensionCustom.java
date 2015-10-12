package no.difi.certvalidator.testutil;


import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;

public interface X509ExtensionCustom {
    void setup(X509v3CertificateBuilder v3CertGen) throws CertIOException;
}
