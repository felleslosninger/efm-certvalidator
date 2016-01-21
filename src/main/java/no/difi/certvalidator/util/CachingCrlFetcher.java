package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.CrlCache;
import no.difi.certvalidator.api.CrlFetcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

/**
 * Default implementation of CRL fetcher, which caches downloaded CRLs. If a CRL is not cached, or the Next update-
 * field of a cached CRL indicates there is an updated CRL available, an updated CRL will immediately be downloaded.
 */
public class CachingCrlFetcher implements CrlFetcher {

    private static final Logger logger = LoggerFactory.getLogger(CrlFetcher.class);

    private static CertificateFactory certificateFactory;

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to create X.509 certificate factory", e);
        }
    }

    private CrlCache crlCache;

    public CachingCrlFetcher(CrlCache crlCache) {
        this.crlCache = crlCache;
    }

    @Override
    public X509CRL get(String url) throws CertificateValidationException{
        X509CRL crl = crlCache.get(url);
        if (crl == null) {
            crl = notInCache(url);
        } else if (crl.getNextUpdate() != null && crl.getNextUpdate().getTime() < System.currentTimeMillis()) {
            crl = outdated(url, crl);
        } else if (crl.getNextUpdate() == null) {
            logger.warn("Next update not set for CRL with URL \"{}\"", url);
        }
        return crl;
    }

    protected X509CRL notInCache(String url) throws CertificateValidationException {
        return download(url);
    }

    protected X509CRL outdated(String url, X509CRL outdatedCrl) throws CertificateValidationException {
        return download(url);
    }

    protected X509CRL download(String url) throws CertificateValidationException {
        logger.debug("Downloading CRL from {}...", url);

        try {
            if (url.startsWith("http://") || url.startsWith("https://")) {
                X509CRL crl = (X509CRL) certificateFactory.generateCRL(URI.create(url).toURL().openStream());
                crlCache.set(url, crl);
                return crl;
            } else if (url.startsWith("ldap://"))
                // Currently not supported.
                return null;
        } catch (Exception e) {
            throw new CertificateValidationException(
                    "Failed to download CRL " + url + (e.getMessage() != null ? (": " + e.getMessage()) : ""),
                    e
            );
        }
        return null;
    }
}
