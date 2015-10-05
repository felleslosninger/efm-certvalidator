package no.difi.virksomhetssertifikat.util;

import no.difi.virksomhetssertifikat.api.CertificateBucketException;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

/**
 * Reads keystore from file for every access to keystore.
 */
public class FileKeystoreCertificateBucket extends KeystoreCertificateBucket {

    private String type;
    private String path;
    private String password;

    public FileKeystoreCertificateBucket(String path, String password) {
        this("JKS", path, password);
    }

    public FileKeystoreCertificateBucket(String type, String path, String password) {
        super(null);

        this.type = type;
        this.path = path.startsWith("file:") ? path.substring(5) : path;
        this.password = password;
    }

    @Override
    protected KeyStore getKeyStore() throws CertificateBucketException {
        try {
            InputStream inputStream = getInputStream();
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(inputStream, password.toCharArray());
            inputStream.close();
            return keyStore;
        } catch (Exception e) {
            throw new CertificateBucketException(e.getMessage(), e);
        }
    }

    protected InputStream getInputStream() throws IOException {
        if (path.startsWith("classpath:")) {
            InputStream inputStream = getClass().getResourceAsStream(path.substring(10));
            if (inputStream == null) {
                throw new IOException(String.format("Unable to read classpath resource from '%s'", path));
            }
            return inputStream;
        } else
            return FileUtils.openInputStream(new File(path));
    }
}
