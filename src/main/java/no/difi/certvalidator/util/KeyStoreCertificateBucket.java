package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CertificateBucket;
import no.difi.certvalidator.api.CertificateBucketException;

import javax.security.auth.x500.X500Principal;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Reads a keystore from input stream and keeps it in memory.
 */
public class KeyStoreCertificateBucket implements CertificateBucket {

    protected KeyStore keyStore;

    public KeyStoreCertificateBucket(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public KeyStoreCertificateBucket(InputStream inputStream, String password) throws CertificateBucketException {
        this("JKS", inputStream, password);
    }

    public KeyStoreCertificateBucket(String type, InputStream inputStream, String password) throws CertificateBucketException {
        try {
            keyStore = KeyStore.getInstance(type);
            keyStore.load(inputStream, password.toCharArray());
            inputStream.close();
        } catch (Exception e) {
            throw new CertificateBucketException(e.getMessage(), e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public X509Certificate findBySubject(X500Principal principal) throws CertificateBucketException{
        for (X509Certificate certificate : this)
            if (certificate.getSubjectX500Principal().equals(principal))
                return certificate;

        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<X509Certificate> iterator() {
        try {
            final KeyStore keyStore = getKeyStore();
            final Enumeration<String> aliases = keyStore.aliases();

            return new Iterator<X509Certificate>() {
                @Override
                public boolean hasNext() {
                    return aliases.hasMoreElements();
                }

                @Override
                public X509Certificate next() {
                    try {
                        return (X509Certificate) keyStore.getCertificate(aliases.nextElement());
                    } catch (KeyStoreException | NoSuchElementException e) {
                        throw new IllegalStateException(e.getMessage(), e);
                    }
                }

                @Override
                public void remove() {
                    // No action.
                }
            };
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    /**
     * Adding certificates identified by aliases from key store to a SimpleCertificateBucket.
     */
    public void toSimple(SimpleCertificateBucket certificates, String... aliases) throws CertificateBucketException {
        try {
            List<String> aliasesList = Arrays.asList(aliases);

            KeyStore keyStore = getKeyStore();
            Enumeration<String> aliasesEnumeration = keyStore.aliases();
            while (aliasesEnumeration.hasMoreElements()) {
                String alias = aliasesEnumeration.nextElement();
                if (aliasesList.contains(alias))
                    certificates.add((X509Certificate) keyStore.getCertificate(alias));
            }
        } catch (Exception e) {
            throw new CertificateBucketException(e.getMessage(), e);
        }
    }

    /**
     * Create a new SimpleCertificateBucket and adding certificates based on aliases.
     */
    public SimpleCertificateBucket toSimple(String... aliases) throws CertificateBucketException {
        SimpleCertificateBucket certificates = new SimpleCertificateBucket();
        toSimple(certificates, aliases);
        return certificates;
    }

    /**
     * Adding certificates identified by prefix(es) from key store to a SimpleCertificateBucket.
     */
    public void startsWith(SimpleCertificateBucket certificates, String... prefix) throws CertificateBucketException {
        try {
            KeyStore keyStore = getKeyStore();
            Enumeration<String> aliasesEnumeration = keyStore.aliases();
            while (aliasesEnumeration.hasMoreElements()) {
                String alias = aliasesEnumeration.nextElement();
                for (String p : prefix)
                    if (alias.startsWith(p))
                        certificates.add((X509Certificate) keyStore.getCertificate(alias));
            }
        } catch (Exception e) {
            throw new CertificateBucketException(e.getMessage(), e);
        }
    }

    /**
     * Create a new SimpleCertificateBucket and adding certificates based on prefix(es).
     */
    public SimpleCertificateBucket startsWith(String... prefix) throws CertificateBucketException {
        SimpleCertificateBucket certificates = new SimpleCertificateBucket();
        startsWith(certificates, prefix);
        return certificates;
    }

    /**
     * Allows for overriding method of fetching key store when used.
     */
    protected KeyStore getKeyStore() throws CertificateBucketException {
        return keyStore;
    }
}
