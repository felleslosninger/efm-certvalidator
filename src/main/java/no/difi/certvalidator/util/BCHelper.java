package no.difi.certvalidator.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * @author erlend
 */
public class BCHelper {

    public static final Provider PROVIDER;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            Security.addProvider(new BouncyCastleProvider());

        PROVIDER = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
}
