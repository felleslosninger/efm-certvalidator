package no.difi.certvalidator;

import no.difi.certvalidator.api.*;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.rule.*;
import no.difi.certvalidator.structure.Junction;
import no.difi.certvalidator.util.*;
import no.difi.xsd.certvalidator._1.*;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class ValidatorLoaderParser {

    private static JAXBContext jaxbContext;

    static {
        try {
            jaxbContext = JAXBContext.newInstance(ValidatorReceipt.class);
        } catch (JAXBException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static ValidatorGroup parse(InputStream inputStream, Map<String, Object> objectStorage)
            throws ValidatorParsingException {
        try {
            ValidatorReceipt receipt = jaxbContext.createUnmarshaller()
                    .unmarshal(new StreamSource(inputStream), ValidatorReceipt.class)
                    .getValue();

            loadKeyStores(receipt, objectStorage);
            loadBuckets(receipt, objectStorage);

            Map<String, ValidatorRule> rulesMap = new HashMap<>();

            for (ValidatorType validatorType : receipt.getValidator()) {
                ValidatorRule validatorRule = parse(validatorType.getChainOrClazzOrCriticalExtensionRecognized(), objectStorage, JunctionEnum.AND);

                String name = validatorType.getName() == null ? "default" : validatorType.getName();
                rulesMap.put(name, validatorRule);
                objectStorage.put(String.format("#validator::%s", name), validatorRule);
            }

            return new ValidatorGroup(rulesMap, receipt.getName(), receipt.getVersion());
        } catch (JAXBException | CertificateValidationException e) {
            throw new ValidatorParsingException(e.getMessage(), e);
        }
    }

    private static void loadKeyStores(ValidatorReceipt receipt, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        for (KeyStoreType keyStoreType : receipt.getKeyStore()) {
            objectStorage.put(
                    String.format("#keyStore::%s", keyStoreType.getName() == null ? "default" : keyStoreType.getName()),
                    new KeyStoreCertificateBucket(
                            new ByteArrayInputStream(keyStoreType.getValue()),
                            keyStoreType.getPassword()
                    )
            );
        }
    }

    private static void loadBuckets(ValidatorReceipt receipt, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        for (CertificateBucketType certificateBucketType : receipt.getCertificateBucket()) {
            SimpleCertificateBucket certificateBucket = new SimpleCertificateBucket();

            for (Object o : certificateBucketType.getCertificateOrCertificateReferenceOrCertificateStartsWith()) {
                if (o instanceof CertificateType) {
                    certificateBucket.add(Validator.getCertificate(((CertificateType) o).getValue()));
                } else if (o instanceof CertificateReferenceType) {
                    CertificateReferenceType c = (CertificateReferenceType) o;
                    for (X509Certificate certificate :
                            getKeyStore(c.getKeyStore(), objectStorage).toSimple(c.getValue()))
                        certificateBucket.add(certificate);
                } else /* if (o instanceof CertificateStartsWithType) */ {
                    CertificateStartsWithType c = (CertificateStartsWithType) o;
                    for (X509Certificate certificate :
                            getKeyStore(c.getKeyStore(), objectStorage).startsWith(c.getValue()))
                        certificateBucket.add(certificate);
                }
            }

            objectStorage.put(String.format("#bucket::%s", certificateBucketType.getName()), certificateBucket);
        }
    }

    private static ValidatorRule parse(List<Object> rules, Map<String, Object> objectStorage,
                                       JunctionEnum junctionEnum) throws CertificateValidationException {
        List<ValidatorRule> ruleList = new ArrayList<>();

        for (Object rule : rules) {
            if (rule instanceof ChainType) {
                ruleList.add(parse((ChainType) rule, objectStorage));
            } else if (rule instanceof ClassType) {
                ruleList.add(parse((ClassType) rule));
            } else if (rule instanceof CriticalExtensionRecognizedType) {
                ruleList.add(parse((CriticalExtensionRecognizedType) rule));
            } else if (rule instanceof CriticalExtensionRequiredType) {
                ruleList.add(parse((CriticalExtensionRequiredType) rule));
            } else if (rule instanceof CRLType) {
                ruleList.add(parse((CRLType) rule, objectStorage));
            } else if (rule instanceof ExpirationType) {
                ruleList.add(parse((ExpirationType) rule));
            } else if (rule instanceof JunctionType) {
                ruleList.add(parse((JunctionType) rule, objectStorage));
            } else if (rule instanceof OCSPType) {
                ruleList.add(parse((OCSPType) rule, objectStorage));
            } else if (rule instanceof PrincipleNameType) {
                ruleList.add(parse((PrincipleNameType) rule, objectStorage));
            } else if (rule instanceof RuleReferenceType) {
                ruleList.add(parse((RuleReferenceType) rule, objectStorage));
            } else if (rule instanceof SigningType) {
                ruleList.add(parse((SigningType) rule));
            } else /* if (rule instanceof ValidatorReferenceType) */ {
                ruleList.add(parse((ValidatorReferenceType) rule, objectStorage));
            }
        }

        switch (junctionEnum) {
            case AND:
                return Junction.and(ruleList.toArray(new ValidatorRule[ruleList.size()]));
            case OR:
                return Junction.or(ruleList.toArray(new ValidatorRule[ruleList.size()]));
            case XOR:
                return Junction.xor(ruleList.toArray(new ValidatorRule[ruleList.size()]));
            default:
                return null;
        }
    }

    private static ValidatorRule parse(ChainType rule, Map<String, Object> objectStorage) {
        return new ChainRule(
                getBucket(rule.getRootBucketReference().getValue(), objectStorage),
                getBucket(rule.getIntermediateBucketReference().getValue(), objectStorage),
                rule.getPolicy().toArray(new String[rule.getPolicy().size()])
        );
    }

    private static ValidatorRule parse(ClassType rule) throws CertificateValidationException {
        try {
            return (ValidatorRule) Class.forName(rule.getValue()).newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new CertificateValidationException(String.format("Unable to load rule '%s'.", rule.getValue()), e);
        }
    }

    private static ValidatorRule parse(CriticalExtensionRecognizedType rule) {
        return new CriticalExtensionRecognizedRule(rule.getValue().toArray(new String[rule.getValue().size()]));
    }

    private static ValidatorRule parse(CriticalExtensionRequiredType rule) {
        return new CriticalExtensionRequiredRule(rule.getValue().toArray(new String[rule.getValue().size()]));
    }

    private static ValidatorRule parse(CRLType rule, Map<String, Object> objectStorage) {
        if (!objectStorage.containsKey("crlFetcher") && !objectStorage.containsKey("crlCache"))
            objectStorage.put("crlCache", new SimpleCrlCache());

        if (!objectStorage.containsKey("crlFetcher"))
            objectStorage.put("crlFetcher", new SimpleCachingCrlFetcher((CrlCache) objectStorage.get("crlCache")));

        return new CRLRule((CrlFetcher) objectStorage.get("crlFetcher"));
    }

    private static ValidatorRule parse(ExpirationType expirationType) {
        if (expirationType.getMillis() == null)
            return new ExpirationRule();
        else
            return new ExpirationSoonRule(expirationType.getMillis());
    }

    private static ValidatorRule parse(JunctionType junctionType, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        return parse(junctionType.getChainOrClazzOrCriticalExtensionRecognized(),
                objectStorage, junctionType.getType());
    }

    private static ValidatorRule parse(OCSPType ocspType, Map<String, Object> objectStorage) {
        return new OCSPRule(getBucket(ocspType.getIntermediateBucketReference().getValue(), objectStorage));
    }

    private static ValidatorRule parse(RuleReferenceType ruleReferenceType, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        if (!objectStorage.containsKey(ruleReferenceType.getValue()))
            throw new CertificateValidationException(
                    String.format("Rule for '%s' not found.", ruleReferenceType.getValue()));

        return (ValidatorRule) objectStorage.get(ruleReferenceType.getValue());
    }

    private static ValidatorRule parse(SigningType signingType) {
        if (signingType.getType().equals(SigningEnum.SELF_SIGNED))
            return SigningRule.SelfSignedOnly();
        else
            return SigningRule.PublicSignedOnly();
    }

    @SuppressWarnings("unchecked")
    private static ValidatorRule parse(PrincipleNameType principleNameType, Map<String, Object> objectStorage) {
        PrincipalNameProvider<String> principalNameProvider;
        if (principleNameType.getReference() != null)
            principalNameProvider = (PrincipalNameProvider<String>) objectStorage.get(principleNameType.getReference().getValue());
        else
            principalNameProvider = new SimplePrincipalNameProvider(principleNameType.getValue());

        return new PrincipalNameRule(
                principleNameType.getField(),
                principalNameProvider,
                principleNameType.getPrincipal() != null ?
                        PrincipalNameRule.Principal.valueOf(principleNameType.getPrincipal().toString()) : PrincipalNameRule.Principal.SUBJECT
        );
    }

    private static ValidatorRule parse(ValidatorReferenceType validatorReferenceType, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        String identifier = String.format("#validator::%s", validatorReferenceType.getValue());
        if (!objectStorage.containsKey(identifier))
            throw new CertificateValidationException(
                    String.format("Unable to find validator '%s'.", validatorReferenceType.getValue()));

        return (ValidatorRule) objectStorage.get(identifier);
    }

    // HELPERS

    private static KeyStoreCertificateBucket getKeyStore(String name, Map<String, Object> objectStorage) {
        return (KeyStoreCertificateBucket) objectStorage.get(
                String.format("#keyStore::%s", name == null ? "default" : name));
    }

    private static CertificateBucket getBucket(String name, Map<String, Object> objectStorage) {
        return (CertificateBucket) objectStorage.get(String.format("#bucket::%s", name));
    }
}
