package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.Property;
import no.difi.certvalidator.api.Report;
import no.difi.certvalidator.util.SimpleProperty;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SigningRule extends AbstractRule {

    public static final Property<Kind> KIND = SimpleProperty.create();

    private final Kind kind;

    public static SigningRule PublicSignedOnly() {
        return new SigningRule(Kind.PUBLIC_SIGNED_ONLY);
    }

    public static SigningRule SelfSignedOnly() {
        return new SigningRule(Kind.SELF_SIGNED_ONLY);
    }

    public SigningRule() {
        this(Kind.PUBLIC_SIGNED_ONLY);
    }

    public SigningRule(Kind kind) {
        this.kind = kind;
    }

    @Override
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        try {
            if (isSelfSigned(certificate)) {
                // Self signed
                if (kind.equals(Kind.PUBLIC_SIGNED_ONLY))
                    throw new FailedValidationException("Certificate should be publicly signed.");
            } else {
                // Publicly signed
                if (kind.equals(Kind.SELF_SIGNED_ONLY))
                    throw new FailedValidationException("Certificate should be self-signed.");
            }

            report.set(KIND, kind);

            return report;
        } catch (FailedValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }

    /**
     * Source: http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
     */
    public static boolean isSelfSigned(X509Certificate cert) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException e) {
            // Invalid signature --> not self-signed
            // Invalid key --> not self-signed
            return false;
        }
    }

    public enum Kind {
        PUBLIC_SIGNED_ONLY, SELF_SIGNED_ONLY
    }
}
