package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CertificateBucket;
import no.difi.certvalidator.api.CertificateBucketException;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 * Wrapper for certificate bucket. May be used to switch or update certificate buckets on-fly.
 */
public class CertificateBucketWrapper implements CertificateBucket {

    private CertificateBucket certificateBucket;

    public CertificateBucketWrapper(CertificateBucket certificateBucket) {
        this.certificateBucket = certificateBucket;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public X509Certificate findBySubject(X500Principal principal) throws CertificateBucketException {
        return certificateBucket.findBySubject(principal);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<X509Certificate> iterator() {
        return certificateBucket.iterator();
    }

    public CertificateBucket getCertificateBucket() {
        return certificateBucket;
    }

    public void setCertificateBucket(CertificateBucket certificateBucket) {
        this.certificateBucket = certificateBucket;
    }
}
