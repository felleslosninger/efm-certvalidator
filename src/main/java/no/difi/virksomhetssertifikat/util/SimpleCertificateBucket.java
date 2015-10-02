package no.difi.virksomhetssertifikat.util;

import no.difi.virksomhetssertifikat.api.CertificateBucket;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SimpleCertificateBucket implements CertificateBucket {

    private List<X509Certificate> certificates = new ArrayList<>();

    public SimpleCertificateBucket(X509Certificate... certificates) {
        this.certificates.addAll(Arrays.asList(certificates));
    }

    @Override
    public X509Certificate findBySubject(X500Principal principal) {
        for (X509Certificate certificate : certificates)
            if (certificate.getSubjectX500Principal().equals(principal))
                return certificate;
        return null;
    }
}
