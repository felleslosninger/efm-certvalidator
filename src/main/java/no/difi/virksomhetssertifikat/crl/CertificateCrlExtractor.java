package no.difi.virksomhetssertifikat.crl;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private static Logger logger = LoggerFactory.getLogger(CertificateCrlExtractor.class);

    public ArrayList<String> extractAllPossibleCRLUrls(KeyStore ks) throws KeyStoreException, IOException {
        Enumeration<String> aliases = ks.aliases();
        ArrayList<String> urls = new ArrayList<String>();
        while(aliases.hasMoreElements()){
            X509Certificate cert = (X509Certificate) ks.getCertificate(aliases.nextElement());
            try{
                urls.addAll(getDistributionUrls(cert));
            }catch(IllegalArgumentException e){
                logger.info("Cant extract CRL from cert:" + cert.toString());
            }
        }
        return urls;
    }

    public static Collection<? extends String> getDistributionUrls(X509Certificate cert) throws IOException {
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
            throw new IllegalArgumentException("No extension specifying distribution point:" + cert);
        }

        return urls;
    }

}
