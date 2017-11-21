package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CertificateBucket;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * Lightweight implementation using ArrayList to keep certificates in memory.
 */
public class SimpleCertificateBucket implements CertificateBucket {

    private List<X509Certificate> certificates = new ArrayList<>();

    public static CertificateBucket with(X509Certificate... certificates) {
        return new SimpleCertificateBucket(certificates);
    }

    public SimpleCertificateBucket(X509Certificate... certificates) {
        add(certificates);
    }

    /**
     * Append certificate(s) to bucket.
     *
     * @param certificates Certificate(s) to be added.
     */
    public void add(X509Certificate... certificates) {
        this.certificates.addAll(Arrays.asList(certificates));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public X509Certificate findBySubject(X500Principal principal) {
        for (X509Certificate certificate : certificates)
            if (certificate.getSubjectX500Principal().equals(principal))
                return certificate;
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<X509Certificate> iterator() {
        return certificates.iterator();
    }
}
