package no.difi.virksomhetssertifikat.crl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;

/**
 * Utility for å hente ut crl url fra et sertifikat.
 */
public class CertificateCrlExtractor {
    private static final Log LOG = LogFactory.getLog(CertificateCrlExtractor.class.getName());

    public ArrayList<String> extractAllPossibleCRLUrls(KeyStore ks) throws KeyStoreException, IOException {
        Enumeration<String> aliases = ks.aliases();
        ArrayList<String> urls = new ArrayList<String>();
        while(aliases.hasMoreElements()){
            X509Certificate cert = (X509Certificate) ks.getCertificate(aliases.nextElement());
            try{
                urls.addAll(getDistributionUrls(cert));
            }catch(IllegalArgumentException e){
                LOG.info("Cant extract CRL from cert:" + cert.toString());
            }
        }
        return urls;
    }

    private Collection<? extends String> getDistributionUrls(X509Certificate cert) throws IOException {
        ArrayList<String> urls = new ArrayList<String>();

        byte[] cdp = cert.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        if (cdp != null)
        {
            try
            {
                // Wraps the raw data in a container class
                CRLDistPoint crldp = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(cdp));

                DistributionPoint[] distPoints = crldp.getDistributionPoints();

                for (DistributionPoint dp : distPoints)
                {
                    // Only use the "General name" data in the distribution point entry.
                    GeneralNames gns = (GeneralNames) dp.getDistributionPoint().getName();

                    for (GeneralName name : gns.getNames())
                    {
                        // Only retrieve URLs
                        if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
                        {
                            DERIA5String s = (DERIA5String) name.getName();
                            urls.add(s.getString());
                        }
                    }
                }
            } catch (IOException e) {
                throw e;
            }
        }else{
            throw new IllegalArgumentException("No extention specifying distribution point:" + cert);
        }

        return urls;
    }

}
