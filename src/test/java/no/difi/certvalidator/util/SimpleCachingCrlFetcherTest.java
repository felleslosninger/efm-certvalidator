package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.CrlCache;
import no.difi.certvalidator.api.CrlFetcher;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509CRL;
import java.util.Date;

public class SimpleCachingCrlFetcherTest {

    @Test
    public void ldapNotSupported() throws Exception {
        CrlFetcher crlFetcher = new SimpleCachingCrlFetcher(new SimpleCrlCache());

        Assert.assertNull(crlFetcher.get("ldap://something..."));
    }

    @Test
    public void returnSameIfNoNextUpdate() throws Exception {
        CrlCache crlCache = new SimpleCrlCache();
        CrlFetcher crlFetcher = new SimpleCachingCrlFetcher(crlCache);

        X509CRL x509CRL = Mockito.mock(X509CRL.class);
        Mockito.doReturn(null).when(x509CRL).getNextUpdate();

        crlCache.set("url", x509CRL);

        Assert.assertEquals(crlFetcher.get("url"), x509CRL);
    }

    @Test
    public void returnNullIfNotValidAndProtocolNotSupported() throws Exception {
        CrlCache crlCache = new SimpleCrlCache();
        CrlFetcher crlFetcher = new SimpleCachingCrlFetcher(crlCache);

        X509CRL x509CRL = Mockito.mock(X509CRL.class);
        Mockito.doReturn(new Date()).when(x509CRL).getNextUpdate();

        Thread.sleep(25);

        crlCache.set("url", x509CRL);

        Assert.assertNull(crlFetcher.get("url"));
    }

    @Test(enabled = false, expectedExceptions = CertificateValidationException.class)
    public void triggerExceptionWithoutMessage() throws Exception {
        CrlCache crlCache = Mockito.mock(CrlCache.class);
        CrlFetcher crlFetcher = new SimpleCachingCrlFetcher(crlCache);

        crlFetcher.get(null);
    }
}
