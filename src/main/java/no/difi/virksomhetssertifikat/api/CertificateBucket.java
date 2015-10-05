package no.difi.virksomhetssertifikat.api;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Iterator;

public interface CertificateBucket extends Iterable<X509Certificate> {
    X509Certificate findBySubject(X500Principal principal) throws CertificateBucketException;
}
