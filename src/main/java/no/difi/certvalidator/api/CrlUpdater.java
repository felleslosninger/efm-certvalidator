package no.difi.certvalidator.api;

import java.security.cert.X509CRL;

public interface CrlUpdater {

    X509CRL update(String url, X509CRL crl) throws CrlUpdateException;

    class CrlUpdateException extends RuntimeException {

        public CrlUpdateException(String message) {
            super(message);
        }

        public CrlUpdateException(String message, Throwable cause) {
            super(message, cause);
        }

    }

}
