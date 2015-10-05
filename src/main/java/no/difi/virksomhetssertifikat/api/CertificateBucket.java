package no.difi.virksomhetssertifikat.api;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 * Defines bucket for certificate allowing customized storage of certificates.
 */
public interface CertificateBucket extends Iterable<X509Certificate> {
    /**
     * Find certificate by subject.
     *
     * @param principal Principal representing certificate to be found.
     * @return Certificate if found, otherwise null.
     * @throws CertificateBucketException
     */
    X509Certificate findBySubject(X500Principal principal) throws CertificateBucketException;
}
