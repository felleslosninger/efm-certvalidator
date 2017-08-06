package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.util.KeyUsage;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author erlend
 */
public class KeyUsageRule extends AbstractRule {

    private KeyUsage[] expectedKeyUsages;

    private boolean[] expected = new boolean[9];

    public KeyUsageRule(KeyUsage... keyUsages) {
        this.expectedKeyUsages = keyUsages;

        for (KeyUsage keyUsage : keyUsages)
            this.expected[keyUsage.getBit()] = true;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        boolean[] found = certificate.getKeyUsage();

        if (!Arrays.equals(expected, found))
            throw new FailedValidationException(String.format("Expected %s, found %s.",
                    Arrays.toString(this.expectedKeyUsages), Arrays.toString(prettyprint(found))));
    }

    private KeyUsage[] prettyprint(boolean[] ku) {
        List<KeyUsage> keyUsages = new ArrayList<>();

        for (int i = 0; i < ku.length; i++)
            if (ku[i])
                keyUsages.add(KeyUsage.of(i));

        return keyUsages.toArray(new KeyUsage[keyUsages.size()]);
    }
}
