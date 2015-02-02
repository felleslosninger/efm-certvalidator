package no.difi.virksomhetssertifikat;


import org.junit.Test;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.junit.Assert.fail;

public class DifiKeyStoreUtilTest {


    public static final String GONE_JKS = "classpath:missing.jks";

    @Test
    public void shouldFailWithErrorMessageOnMissingIntermediate() throws CertificateException {
        try {
            DifiKeyStoreUtil util = new DifiKeyStoreUtil("classpath:minssing.jks", "", "JKS", GONE_JKS, "", "JKS");
            util.loadIntermediateCertsKeystore();
            fail(); // should cast IOexception wrapped in VirksomhetsValidationException
        } catch (NoSuchAlgorithmException e) {
            fail();
        } catch (IOException e) {
            // ok !!
        } catch (KeyStoreException e) {
            fail();
        }
    }

    @Test
    public void shouldFailWithErrorMessageOnMissingCA() throws CertificateException {
        try {
            DifiKeyStoreUtil util = new DifiKeyStoreUtil("classpath:minssing.jks", "", "JKS", GONE_JKS, "", "JKS");
            util.loadCaCertsKeystore();
            fail(); // should cast IOexception wrapped in VirksomhetsValidationException
        } catch (NoSuchAlgorithmException e) {
            fail();
        } catch (IOException e) {
            // ok !!
        } catch (KeyStoreException e) {
            fail();
        }


    }

}
