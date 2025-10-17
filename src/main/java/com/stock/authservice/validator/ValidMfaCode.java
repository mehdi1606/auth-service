package com.stock.authservice.validator;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = MfaCodeValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidMfaCode {

    String message() default "Invalid MFA code format";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    int codeLength() default 6;
}
