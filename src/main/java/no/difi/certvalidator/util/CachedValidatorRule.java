package no.difi.certvalidator.util;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.Report;
import no.difi.certvalidator.api.ValidatorRule;

import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

public class CachedValidatorRule extends CacheLoader<X509Certificate, CachedValidatorRule.Result>
        implements ValidatorRule {

    private ValidatorRule validatorRule;

    private LoadingCache<X509Certificate, Result> cache;

    public CachedValidatorRule(ValidatorRule validatorRule, long timeout) {
        this.validatorRule = validatorRule;

        cache = CacheBuilder.newBuilder()
                .expireAfterWrite(timeout, TimeUnit.SECONDS)
                .build(this);
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        cache.getUnchecked(certificate).trigger();
    }

    @Override
    public Report validate(X509Certificate certificate, Report report) throws CertificateValidationException {
        validate(certificate);

        return report;
    }

    @Override
    public Result load(X509Certificate certificate) throws Exception {
        try {
            validatorRule.validate(certificate);
            return new Result();
        } catch (CertificateValidationException e) {
            return new Result(e);
        }
    }

    protected class Result {

        private CertificateValidationException exception;

        public Result() {
            // No action.
        }

        public Result(CertificateValidationException e) {
            this.exception = e;
        }

        public void trigger() throws CertificateValidationException {
            if (exception != null)
                throw exception;
        }
    }
}
