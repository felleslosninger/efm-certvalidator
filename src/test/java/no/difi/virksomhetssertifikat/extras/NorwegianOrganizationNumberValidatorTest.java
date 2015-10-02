package no.difi.virksomhetssertifikat.extras;


import no.difi.virksomhetssertifikat.api.PrincipalNameProvider;
import no.difi.virksomhetssertifikat.testutil.X509TestGenerator;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;

public class NorwegianOrganizationNumberValidatorTest extends X509TestGenerator {

    private static Logger logger = LoggerFactory.getLogger(NorwegianOrganizationNumberValidatorTest.class);

    @Test
    public void shouldExtractOrgnumberFromCertBasedOnSerialnumber() throws Exception {
        final String ORGNR = "123456789";
        X509Certificate cert = createX509Certificate("CN=name, OU=None, O=None L=None, C=None, serialNumber=" + ORGNR);
        logger.debug(cert.getSubjectDN().toString());

        new NorwegianOrganizationNumberValidator(new PrincipalNameProvider() {
            @Override
            public boolean validate(String value) {
                logger.info(value);
                Assert.assertEquals(ORGNR, value);
                return true;
            }
        }).validate(cert);
    }

    @Test
    public void shouldExtractOrgnumberFromCertBasedOnOrgNumberInOrganiation() throws Exception {
        final String ORGNR = "123456789";
        X509Certificate cert = createX509Certificate("CN=name, OU=None, O=organisasjon - " + ORGNR + ", L=None, C=None");
        logger.debug(cert.getSubjectDN().toString());

        new NorwegianOrganizationNumberValidator(new PrincipalNameProvider() {
            @Override
            public boolean validate(String value) {
                logger.info(value);
                Assert.assertEquals(ORGNR, value);
                return true;
            }
        }).validate(cert);
    }

    @Test
    public void shouldExtractOrgnumberFromComfidesCert() throws Exception {
        final String ORGNR = "399573952";
        X509Certificate cert = createX509Certificate("C=NO,ST=AKERSHUS,L=FORNEBUVEIEN 1\\, 1366 LYSAKER,O=RF Commfides,SERIALNUMBER=399573952,CN=RF Commfides");
        logger.debug(cert.getSubjectDN().toString());

        new NorwegianOrganizationNumberValidator(new PrincipalNameProvider() {
            @Override
            public boolean validate(String value) {
                logger.info(value);
                Assert.assertEquals(ORGNR, value);
                return true;
            }
        }).validate(cert);
    }
}
