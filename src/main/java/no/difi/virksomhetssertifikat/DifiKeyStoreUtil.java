package no.difi.virksomhetssertifikat;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class DifiKeyStoreUtil {
    private String cacertsType;
    private String intermediateType;
    private InputStream caResource;
    private String caPassword;
    private InputStream intermediateResource;
    private String intermediatePassword;



    public DifiKeyStoreUtil(InputStream caResource, String keystorePassword, String cacertsType, InputStream intermediateResource, String intermediatePassword, String intermediateType) {

        this.caResource = caResource;
        this.caPassword = keystorePassword;
        this.cacertsType = cacertsType;

        this.intermediateResource = intermediateResource;
        this.intermediatePassword = intermediatePassword;
        this.intermediateType = intermediateType;
    }


    public KeyStore loadCaCertsKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore jks = KeyStore.getInstance(cacertsType);
        InputStream is = caResource;
        jks.load(is, caPassword.toCharArray());
        is.close();
        return jks;
    }

    public KeyStore loadIntermediateCertsKeystore() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore jks = KeyStore.getInstance(intermediateType);
        InputStream is = intermediateResource;
        jks.load(is, intermediatePassword.toCharArray());
        is.close();
        return jks;

    }
}
