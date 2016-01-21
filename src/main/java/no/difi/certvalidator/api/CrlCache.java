package no.difi.certvalidator.api;

import java.security.cert.X509CRL;

public interface CrlCache extends CrlFetcher {
    void set(String url, X509CRL crl);
}
