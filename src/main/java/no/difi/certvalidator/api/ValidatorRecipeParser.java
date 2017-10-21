package no.difi.certvalidator.api;

import no.difi.certvalidator.jaxb.ValidatorRecipe;
import no.difi.certvalidator.lang.ValidatorParsingException;

import java.util.Map;

/**
 * @author erlend
 */
public interface ValidatorRecipeParser {

    void parse(ValidatorRecipe validatorRecipe, Map<String, Object> objectStorage) throws ValidatorParsingException;

}
