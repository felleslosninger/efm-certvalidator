package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.CrlCache;
import no.difi.certvalidator.api.CrlFetcher;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;

/**
 * Simple implementation of CRL fetcher, which caches downloaded CRLs. If a CRL is not cached, or the Next update-
 * field of a cached CRL indicates there is an updated CRL available, an updated CRL will immediately be downloaded.
 */
public class SimpleCachingCrlFetcher implements CrlFetcher {

    protected CrlCache crlCache;

    public SimpleCachingCrlFetcher(CrlCache crlCache) {
        this.crlCache = crlCache;
    }

    @Override
    public X509CRL get(String url) throws CertificateValidationException {
        X509CRL crl = crlCache.get(url);
        if (crl == null) {
            // Not in cache
            crl = download(url);
        } else if (crl.getNextUpdate() != null && crl.getNextUpdate().getTime() < System.currentTimeMillis()) {
            // Outdated
            crl = download(url);
        } else if (crl.getNextUpdate() == null) {
            // No action.
        }
        return crl;
    }

    protected X509CRL download(String url) throws CertificateValidationException {
        if (url != null && url.matches("http[s]{0,1}://.*")) {
            X509CRL crl = httpDownload(url);
            crlCache.set(url, crl);
            return crl;
        } else if (url != null && url.startsWith("ldap://")) {
            // Currently not supported.
            return null;
        }

        return null;
    }

    protected X509CRL httpDownload(String url) throws CertificateValidationException {
        try {
            return CrlUtils.load(URI.create(url).toURL().openStream());
        } catch (IOException | CRLException e) {
            throw new CertificateValidationException(String.format("Failed to download CRL '%s' (%s)", url, e.getMessage()), e);
        }
    }
}
