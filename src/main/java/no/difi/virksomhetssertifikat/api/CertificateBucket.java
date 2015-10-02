package no.difi.virksomhetssertifikat.api;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

public interface CertificateBucket {

    X509Certificate findBySubject(X500Principal principal) throws CertificateBucketException;

}
