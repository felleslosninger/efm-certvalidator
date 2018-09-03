package no.difi.certvalidator;

import net.klakegg.pkix.ocsp.OcspClient;
import net.klakegg.pkix.ocsp.api.OcspFetcher;
import net.klakegg.pkix.ocsp.builder.Builder;
import no.difi.certvalidator.api.*;
import no.difi.certvalidator.jaxb.*;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.rule.*;
import no.difi.certvalidator.structure.Junction;
import no.difi.certvalidator.util.CachedValidatorRule;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.stream.StreamSource;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

class ValidatorLoaderParser {

    private static JAXBContext jaxbContext;

    private static List<ValidatorRecipeParser> recipeParser = serviceLoader(ValidatorRecipeParser.class);

    private static List<ValidatorRuleParser> ruleParsers = serviceLoader(ValidatorRuleParser.class);

    static {
        try {
            jaxbContext = JAXBContext.newInstance(ValidatorRecipe.class);
        } catch (JAXBException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static ValidatorGroup parse(InputStream inputStream, Map<String, Object> objectStorage)
            throws ValidatorParsingException {
        try {
            ValidatorRecipe recipe = jaxbContext.createUnmarshaller()
                    .unmarshal(new StreamSource(inputStream), ValidatorRecipe.class)
                    .getValue();

            for (ValidatorRecipeParser parser : recipeParser)
                parser.parse(recipe, objectStorage);

            Map<String, ValidatorRule> rulesMap = new HashMap<>();

            for (ValidatorType validatorType : recipe.getValidator()) {
                ValidatorRule validatorRule = parse(validatorType.getBlacklistOrCachedOrChain(), objectStorage, JunctionEnum.AND);

                if (validatorType.getTimeout() != null)
                    validatorRule = new CachedValidatorRule(validatorRule, validatorType.getTimeout());

                String name = validatorType.getName() == null ? "default" : validatorType.getName();
                rulesMap.put(name, validatorRule);
                objectStorage.put(String.format("#validator::%s", name), validatorRule);
            }

            return new ValidatorGroup(rulesMap, recipe.getName(), recipe.getVersion());
        } catch (JAXBException | CertificateValidationException e) {
            throw new ValidatorParsingException(e.getMessage(), e);
        }
    }

    private static ValidatorRule parse(List<Object> rules, Map<String, Object> objectStorage,
                                       JunctionEnum junctionEnum) throws CertificateValidationException {
        List<ValidatorRule> ruleList = new ArrayList<>();

        for (Object rule : rules)
            ruleList.add(parse(rule, objectStorage));

        if (junctionEnum == JunctionEnum.AND)
            return Junction.and(ruleList.toArray(new ValidatorRule[ruleList.size()]));
        else if (junctionEnum == JunctionEnum.OR)
            return Junction.or(ruleList.toArray(new ValidatorRule[ruleList.size()]));
        else // if (junctionEnum == JunctionEnum.XOR)
            return Junction.xor(ruleList.toArray(new ValidatorRule[ruleList.size()]));
    }

    private static ValidatorRule parse(Object rule, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        if (rule instanceof BlacklistType)
            return parse((BlacklistType) rule, objectStorage);
        else if (rule instanceof CachedType)
            return parse((CachedType) rule, objectStorage);
        else if (rule instanceof ChainType)
            return parse((ChainType) rule, objectStorage);
        else if (rule instanceof JunctionType)
            return parse((JunctionType) rule, objectStorage);
        else if (rule instanceof OCSPType)
            return parse((OCSPType) rule, objectStorage);
        else if (rule instanceof HandleErrorType)
            return parse((HandleErrorType) rule, objectStorage);
        else if (rule instanceof TryType)
            return parse((TryType) rule, objectStorage);
        else if (rule instanceof WhitelistType)
            return parse((WhitelistType) rule, objectStorage);
        else {
            for (ValidatorRuleParser parser : ruleParsers)
                if (parser.supports(rule.getClass()))
                    return parser.parse(rule, objectStorage);
        }

        throw new ValidatorParsingException(String.format("Unable to parse '%s'", rule));
    }

    private static ValidatorRule parse(BlacklistType rule, Map<String, Object> objectStorage) {
        return new BlacklistRule(getBucket(rule.getValue(), objectStorage));
    }

    private static ValidatorRule parse(CachedType rule, Map<String, Object> objectStorage) throws
            CertificateValidationException {
        return new CachedValidatorRule(
                parse(rule.getBlacklistOrCachedOrChain(), objectStorage, JunctionEnum.AND),
                rule.getTimeout()
        );
    }

    private static ValidatorRule parse(ChainType rule, Map<String, Object> objectStorage) {
        return new ChainRule(
                getBucket(rule.getRootBucketReference().getValue(), objectStorage),
                getBucket(rule.getIntermediateBucketReference().getValue(), objectStorage),
                rule.getPolicy().toArray(new String[rule.getPolicy().size()])
        );
    }

    private static ValidatorRule parse(HandleErrorType optionalType, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        List<ValidatorRule> validatorRules = new ArrayList<>();
        for (Object o : optionalType.getBlacklistOrCachedOrChain())
            validatorRules.add(parse(o, objectStorage));

        String handlerKey = optionalType.getHandler() != null ? optionalType.getHandler() : "#errorhandler";

        if (objectStorage.get(handlerKey) != null)
            return new HandleErrorRule((ErrorHandler) objectStorage.get(handlerKey), validatorRules);
        else
            return new HandleErrorRule(validatorRules);
    }

    private static ValidatorRule parse(JunctionType junctionType, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        return parse(junctionType.getBlacklistOrCachedOrChain(),
                objectStorage, junctionType.getType());
    }

    private static ValidatorRule parse(OCSPType ocspType, Map<String, Object> objectStorage) {
        Builder<OcspClient> builder = OcspClient.builder();

        builder = builder.set(OcspClient.INTERMEDIATES, getBucket(ocspType.getIntermediateBucketReference().getValue(), objectStorage)
                .asList());

        if (objectStorage.containsKey("ocsp_fetcher"))
            builder = builder.set(OcspClient.FETCHER, (OcspFetcher) objectStorage.get("ocsp_fetcher"));

        return new OCSPRule(builder.build());
    }

    private static ValidatorRule parse(TryType tryType, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        for (Object rule : tryType.getBlacklistOrCachedOrChain()) {
            try {
                return parse(rule, objectStorage);
            } catch (Exception e) {
                // No action
            }
        }

        throw new CertificateValidationException("Unable to find valid rule in try.");
    }

    private static ValidatorRule parse(WhitelistType rule, Map<String, Object> objectStorage)
            throws CertificateValidationException {
        return new WhitelistRule(getBucket(rule.getValue(), objectStorage));
    }

    // HELPERS

    private static CertificateBucket getBucket(String name, Map<String, Object> objectStorage) {
        return (CertificateBucket) objectStorage.get(String.format("#bucket::%s", name));
    }

    public static <T> List<T> serviceLoader(Class<T> cls) {
        return StreamSupport.stream(ServiceLoader.load(cls).spliterator(), false)
                .sorted((o1, o2) -> {
                    int v1 = o1.getClass().isAnnotationPresent(Order.class) ?
                            o1.getClass().getAnnotation(Order.class).value() : 0;
                    int v2 = o2.getClass().isAnnotationPresent(Order.class) ?
                            o2.getClass().getAnnotation(Order.class).value() : 0;

                    return Integer.compare(v1, v2);
                })
                .collect(Collectors.toList());
    }
}
