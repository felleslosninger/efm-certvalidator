package no.difi.virksomhetssertifikat.rule;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.ValidatorRule;
import no.difi.virksomhetssertifikat.api.CrlCache;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.util.SimpleCrlCache;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

public class CRLRule implements ValidatorRule {

    private static final Logger logger = LoggerFactory.getLogger(CRLRule.class);

    private static final String CRL_EXTENSION = "2.5.29.31";

    private static CertificateFactory certificateFactory;

    private CrlCache crlCache;

    public CRLRule(CrlCache crlCache) {
        this.crlCache = crlCache;
    }

    public CRLRule() {
        this(new SimpleCrlCache());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        List<String> urls = getCrlDistributionPoints(certificate);
        for (String url : urls) {
            X509CRL crl = crlCache.get(url);
            if (crl == null || crl.getNextUpdate().getTime() < System.currentTimeMillis()) {
                crl = fetch(url);
                crlCache.set(url, crl);
            }

            if (crl != null && crl.isRevoked(certificate))
                throw new FailedValidationException("Certificate is revoked.");
        }
    }

    public static X509CRL fetch(String url) throws CertificateValidationException {
        logger.debug("Fetching {}", url);

        try {
            if (url.startsWith("http://") || url.startsWith("https://"))
                return load(URI.create(url).toURL().openStream());
            else if (url.startsWith("ldap://"))
                // Currently not supported.
                return null;

        } catch (Exception e) {
            throw new CertificateValidationException(e.getMessage(), e);
        }

        return null;
    }

    public static X509CRL load(InputStream inputStream) throws CertificateValidationException {
        try {
            if (certificateFactory == null)
                certificateFactory = CertificateFactory.getInstance("X.509");

            return (X509CRL) certificateFactory.generateCRL(inputStream);
        } catch (Exception e) {
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }

    public static List<String> getCrlDistributionPoints(X509Certificate certificate) throws CertificateValidationException {
        try {
            ArrayList<String> urls = new ArrayList<String>();

            if (!certificate.getNonCriticalExtensionOIDs().contains(CRL_EXTENSION))
                return urls;

            CRLDistPoint distPoint = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(certificate.getExtensionValue(CRL_EXTENSION)));
            for (DistributionPoint dp : distPoint.getDistributionPoints())
                for (GeneralName name : ((GeneralNames) dp.getDistributionPoint().getName()).getNames())
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier)
                        urls.add(((DERIA5String) name.getName()).getString());

            return urls;
        } catch (IOException e) {
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }
}
