package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CrlCache;

import java.security.cert.X509CRL;
import java.util.Map;
import java.util.TreeMap;

/**
 * In-memory implementation of CRL cache. Used as default implementation.
 */
public class SimpleCrlCache implements CrlCache {

    private Map<String, X509CRL> storage = new TreeMap<>();

    @Override
    public X509CRL get(String url) {
        return storage.get(url);
    }

    @Override
    public void set(String url, X509CRL crl) {
        if (crl == null)
            storage.remove(url);
        else
            storage.put(url, crl);
    }
}
