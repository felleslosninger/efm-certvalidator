package no.difi.virksomhetssertifikat.extras;


import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.api.PrincipalNameProvider;
import no.difi.virksomhetssertifikat.testutil.X509TestGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

public class NorwegianOrganizationNumberRuleTest extends X509TestGenerator {

    private static Logger logger = LoggerFactory.getLogger(NorwegianOrganizationNumberRuleTest.class);

    @Test
    public void shouldExtractOrgnumberFromCertBasedOnSerialnumber() throws Exception {
        final String ORGNR = "123456789";
        X509Certificate cert = createX509Certificate("CN=name, OU=None, O=None L=None, C=None, serialNumber=" + ORGNR);
        logger.debug(cert.getSubjectDN().toString());

        new NorwegianOrganizationNumberRule(new PrincipalNameProvider() {
            @Override
            public boolean validate(String value) {
                logger.info(value);
                Assert.assertEquals(ORGNR, value);
                return true;
            }
        }).validate(cert);
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void invalidOrgnumberFromCertBasedOnSerialnumber() throws Exception {
        final String ORGNR = "123 456 789";
        X509Certificate cert = createX509Certificate("CN=name, OU=None, O=None L=None, C=None, serialNumber=" + ORGNR);
        logger.debug(cert.getSubjectDN().toString());

        new NorwegianOrganizationNumberRule(new PrincipalNameProvider() {
            @Override
            public boolean validate(String value) {
                logger.info(value);
                Assert.fail("Number not expected.");
                return true;
            }
        }).validate(cert);
    }

    @Test
    public void shouldExtractOrgnumberFromCertBasedOnOrgNumberInOrganiation() throws Exception {
        final String ORGNR = "123456789";
        X509Certificate cert = createX509Certificate("CN=name, OU=None, O=organisasjon - " + ORGNR + ", L=None, C=None");
        logger.debug(cert.getSubjectDN().toString());

        new NorwegianOrganizationNumberRule(new PrincipalNameProvider() {
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

        new NorwegianOrganizationNumberRule(new PrincipalNameProvider() {
            @Override
            public boolean validate(String value) {
                logger.info(value);
                Assert.assertEquals(ORGNR, value);
                return true;
            }
        }).validate(cert);
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void attributesNotFound() throws Exception {
        X509Certificate cert = createX509Certificate("CN=name");
        logger.debug(cert.getSubjectDN().toString());

        new NorwegianOrganizationNumberRule(new PrincipalNameProvider() {
            @Override
            public boolean validate(String value) {
                logger.info(value);
                Assert.fail("Number not expected.");
                return true;
            }
        }).validate(cert);
    }

    @Test(expectedExceptions = FailedValidationException.class)
    public void notAcceptedOrgnumberFromCertBasedOnSerialnumber() throws Exception {
        final String ORGNR = "123456789";
        X509Certificate cert = createX509Certificate("CN=name, OU=None, O=None L=None, C=None, serialNumber=" + ORGNR);
        logger.debug(cert.getSubjectDN().toString());

        new NorwegianOrganizationNumberRule(new PrincipalNameProvider() {
            @Override
            public boolean validate(String value) {
                logger.info(value);
                return false;
            }
        }).validate(cert);
    }
}
