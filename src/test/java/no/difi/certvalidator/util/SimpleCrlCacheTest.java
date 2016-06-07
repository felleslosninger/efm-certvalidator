package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CrlCache;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509CRL;

public class SimpleCrlCacheTest {

    @Test
    public void simple() throws Exception {
        CrlCache crlCache = new SimpleCrlCache();
        Assert.assertNull(crlCache.get("http://none/"));

        crlCache.set("http://none/", Mockito.mock(X509CRL.class));
        Assert.assertNotNull(crlCache.get("http://none/"));

        crlCache.set("http://none/", null);
        Assert.assertNull(crlCache.get("http://none/"));
    }

}
