package no.difi.virksomhetssertifikat.util;

import no.difi.virksomhetssertifikat.api.CertificateBucket;
import no.difi.virksomhetssertifikat.api.CertificateBucketException;
import org.apache.commons.io.FileUtils;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class KeystoreCertificateBucket implements CertificateBucket {

    private String type;
    private String path;
    private String password;

    public KeystoreCertificateBucket(String type, String path, String password) {
        this.type = type;
        this.path = path;
        this.password = password;
    }

    @Override
    public X509Certificate findBySubject(X500Principal principal) throws CertificateBucketException{
        try {
            KeyStore keyStore = getKeystore();
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

    protected KeyStore getKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(type);
        InputStream inputStream = toInputStream(path);
        keyStore.load(inputStream, password.toCharArray());
        inputStream.close();
        return keyStore;
    }

    protected InputStream toInputStream(String resource) throws IOException {
        if (resource.startsWith("file:"))
            resource = resource.substring(5);

        if (resource.startsWith("classpath:")) {
            InputStream inputStream = getClass().getResourceAsStream(resource.substring(10));
            if (inputStream == null) {
                throw new IOException("Cant read classpath resource from " + resource);
            }
            return inputStream;
        } else
            return FileUtils.openInputStream(new File(resource));
    }

}
