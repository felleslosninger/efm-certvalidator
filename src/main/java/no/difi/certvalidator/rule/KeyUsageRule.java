package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.util.KeyUsage;

import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * @author erlend
 */
public class KeyUsageRule implements ValidatorRule {

    private boolean[] expected = new boolean[9];

    public KeyUsageRule(KeyUsage... keyUsages) {
        for (KeyUsage keyUsage : keyUsages)
            this.expected[keyUsage.getBit()] = true;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        boolean[] found = certificate.getKeyUsage();

        if (!Arrays.equals(expected, found))
            throw new FailedValidationException(String.format("Expected %s, found %s.",
                    Arrays.toString(this.expected), Arrays.toString(found)));
    }
}
