package no.difi.virksomhetssertifikat.api;

import java.security.cert.X509CRL;

public interface CrlCache {
    X509CRL get(String url);
    void set(String url, X509CRL crl);
}
