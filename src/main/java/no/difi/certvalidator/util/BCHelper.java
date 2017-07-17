package no.difi.certvalidator.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * @author erlend
 */
public class BCHelper {

    private static final Provider PROVIDER;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null) {
            PROVIDER = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        } else {
            PROVIDER = new BouncyCastleProvider();
            Security.addProvider(PROVIDER);
        }
    }

    public static Provider getProvider() {
        return PROVIDER;
    }
}
