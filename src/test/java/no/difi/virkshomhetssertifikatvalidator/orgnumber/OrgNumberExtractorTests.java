package no.difi.virkshomhetssertifikatvalidator.orgnumber;


import no.difi.virksomhetssertifikat.orgnr.OrgNumberExtractor;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Assert;
import org.junit.Test;
import testutil.X509TestGenerator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class OrgNumberExtractorTests extends X509TestGenerator {

    @Test
    public void shouldExtractOrgnumberFromCertBasedOnSerialnumber() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        String ORGNR = "123456789";
        X509Certificate cert = createX509Certificate("CN=name, OU=None, O=None L=None, C=None, serialNumber="+ ORGNR);
        String orgNr = new OrgNumberExtractor().getOrgNumber(cert);

        Assert.assertEquals(ORGNR, orgNr);
    }

    @Test
    public void shouldExtractOrgnumberFromCertBasedOnOrgNumberInOrganiation() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        String ORGNR = "123456789";
        X509Certificate cert = createX509Certificate("CN=name, OU=None, O=organisasjon - "+ ORGNR +", L=None, C=None");
        String orgNr = new OrgNumberExtractor().getOrgNumber(cert);

        Assert.assertEquals(ORGNR, orgNr);
    }

    @Test
    public void shouldExtractOrgnumberFromComfidesCert() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {
        String ORGNR = "399573952";

        X509Certificate cert = createX509Certificate("C=NO,ST=AKERSHUS,L=FORNEBUVEIEN 1\\, 1366 LYSAKER,O=RF Commfides,SERIALNUMBER=399573952,CN=RF Commfides");
        String orgNr = new OrgNumberExtractor().getOrgNumber(cert);

        Assert.assertEquals(ORGNR, orgNr);
    }
}
