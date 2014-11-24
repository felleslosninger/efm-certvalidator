package no.difi.virksomhetssertifikat;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class DifiKeyStoreUtil {
    private String cacertsType;
    private String intermediateType;
    private String caResource;
    private String caPassword;
    private String intermediateResource;
    private String intermediatePassword;

    public DifiKeyStoreUtil(String caResource, String keystorePassword, String cacertsType, String intermediateResource, String intermediatePassword, String intermediateType) {
        this.caResource = caResource;
        this.caPassword = keystorePassword;
        this.cacertsType = cacertsType;

        this.intermediateResource = intermediateResource;
        this.intermediatePassword = intermediatePassword;
        this.intermediateType = intermediateType;
    }


    public KeyStore loadCaCertsKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore jks = KeyStore.getInstance(cacertsType);
        InputStream is = toInputStream(caResource);
        jks.load(is, caPassword.toCharArray());
        is.close();
        return jks;
    }

    public KeyStore loadIntermediateCertsKeystore() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore jks = KeyStore.getInstance(intermediateType);
        InputStream is = toInputStream(intermediateResource);
        jks.load(is, intermediatePassword.toCharArray());
        is.close();
        return jks;

    }

    protected InputStream toInputStream(String intermediateResource) throws IOException {
        if(intermediateResource.startsWith("file:"))
            return FileUtils.openInputStream(new File(intermediateResource.replace("file:", "")));
        else if(intermediateResource.startsWith("classpath:"))
            return this.getClass().getResourceAsStream(intermediateResource.replace("classpath:", ""));
        else
            throw new UnsupportedOperationException("Cant load keystore from, " + intermediateResource);
    }

}
