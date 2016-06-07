package no.difi.certvalidator.rule;

public class CriticalExtensionRule {

    public static CriticalExtensionRecognizedRule recognizes(String... recognizedExtensions) {
        return new CriticalExtensionRecognizedRule(recognizedExtensions);
    }

    public static CriticalExtensionRequiredRule requires(String... requiredExtensions) {
        return new CriticalExtensionRequiredRule(requiredExtensions);
    }

    CriticalExtensionRule() {
        // No action.
    }
}
