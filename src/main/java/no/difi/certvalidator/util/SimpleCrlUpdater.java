package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CrlCache;
import no.difi.certvalidator.api.CrlUpdater;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

public class SimpleCrlUpdater implements CrlUpdater {

    private static final Logger logger = LoggerFactory.getLogger(CrlUpdater.class);
    private CertificateFactory certificateFactory;
    private CrlCache crlCache;

    public SimpleCrlUpdater(CrlCache crlCache) {
        try {
            this.certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to create X.509 certificate factory", e);
        }
        this.crlCache = crlCache;
    }

    @Override
    public X509CRL update(String url, X509CRL crl) {
        if (crl == null || (crl.getNextUpdate() != null && crl.getNextUpdate().getTime() < System.currentTimeMillis())) {
            crl = doUpdate(url);
        } else if (crl.getNextUpdate() == null) {
            logger.warn("Next update not set for CRL with URL \"{}\"", url);
        }
        return crl;
    }

    protected X509CRL doUpdate(String url) throws CrlUpdateException {
        if (logger.isDebugEnabled())
            logger.debug("Downloading CRL from {}...", url);
        try {
            if (url.startsWith("http://") || url.startsWith("https://")) {
                X509CRL crl = (X509CRL)certificateFactory.generateCRL(URI.create(url).toURL().openStream());
                crlCache.set(url, crl);
                return crl;
            } else if (url.startsWith("ldap://"))
                // Currently not supported.
                return null;
        } catch (Exception e) {
            throw new CrlUpdateException(
                    "Failed to download CRL " + url + (e.getMessage() != null ? (": " + e.getMessage()) : ""),
                    e
            );
        }
        return null;
    }

}
