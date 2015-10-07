package no.difi.virksomhetssertifikat.rule;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.ValidatorRule;
import no.difi.virksomhetssertifikat.api.FailedValidationException;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SigningRule implements ValidatorRule {

    public static SigningRule PublicSignedOnly() {
        return new SigningRule(Kind.PUBLIC_SIGNED_ONLY);
    }

    public static SigningRule SelfSignedOnly() {
        return new SigningRule(Kind.SELF_SIGNED_ONLY);
    }

    private Kind kind;

    public SigningRule() {
        this(Kind.PUBLIC_SIGNED_ONLY);
    }

    public SigningRule(Kind kind) {
        this.kind = kind;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
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
        } catch (SignatureException sigEx) {
            // Invalid signature --> not self-signed
            return false;
        } catch (InvalidKeyException keyEx) {
            // Invalid key --> not self-signed
            return false;
        }
    }

    public enum Kind {
        PUBLIC_SIGNED_ONLY, SELF_SIGNED_ONLY
    }
}
