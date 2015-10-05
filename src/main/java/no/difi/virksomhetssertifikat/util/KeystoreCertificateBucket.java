package no.difi.virksomhetssertifikat.util;

import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.api.CertificateBucketException;
import no.difi.virksomhetssertifikat.api.CertificateValidationException;

import javax.security.auth.x500.X500Principal;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

/**
 * Reads a keystore from input stream and keeps it in memory.
 */
public class KeystoreCertificateBucket implements CertificateBucket {

    protected KeyStore keyStore;

    protected KeystoreCertificateBucket(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public KeystoreCertificateBucket(String type, InputStream inputStream, String password) throws CertificateValidationException {
        try {
            keyStore = KeyStore.getInstance(type);
            keyStore.load(inputStream, password.toCharArray());
            inputStream.close();
        } catch (Exception e) {
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate findBySubject(X500Principal principal) throws CertificateBucketException{
        try {
            KeyStore keyStore = getKeyStore();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                X509Certificate possibleIssuer = (X509Certificate) keyStore.getCertificate(aliases.nextElement());
                if (possibleIssuer.getSubjectX500Principal().equals(principal)) {
                    return possibleIssuer;
                }
            }
            return null;
        } catch (Exception e) {
            throw new CertificateBucketException(e.getMessage(), e);
        }
    }

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
                    } catch (KeyStoreException e) {
                        throw new IllegalStateException(e.getMessage(), e);
                    }
                }
            };
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    /**
     * Adding certificates identified by aliases from keystore to a SimpleCertificateBucket.
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
     * Allows for overriding method of fetching keystore when used.
     */
    protected KeyStore getKeyStore() throws CertificateBucketException {
        return keyStore;
    }
}
