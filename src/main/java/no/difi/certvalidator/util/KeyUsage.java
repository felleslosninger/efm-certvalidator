package no.difi.certvalidator.util;

/**
 * From <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.3">RFC5280 4.2.1.3</a>.
 *
 * @author erlend
 */
public enum KeyUsage {

    DIGITAL_SIGNATURE(0),

    NON_REPUDIATION(1),

    KEY_ENCIPHERMENT(2),

    DATA_ENCIPHERMENT(3),

    KEY_AGREEMENT(4),

    KEY_CERT_SIGN(5),

    CRL_SIGN(6),

    ENCIPHER_ONLY(7),

    DECIPHER_ONLY(8);

    private final int bit;

    public static KeyUsage of(int bit) {
        for (KeyUsage keyUsage : values())
            if (keyUsage.bit == bit)
                return keyUsage;

        throw new IllegalArgumentException(String.format("Bit '%s' is not known.", bit));
    }

    KeyUsage(int bit) {
        this.bit = bit;
    }

    public int getBit() {
        return bit;
    }
}
