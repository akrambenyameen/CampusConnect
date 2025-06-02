import joi from 'joi';

// Register Schema
export const registerSchema = joi.object({
    userName: joi.string()
        .alphanum()
        .min(3)
        .max(20)
        .required(),
    email: joi.string()
        .email()
        .required(),
        password: joi.string()
        .min(8)
        .max(32)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%?&]).{8,32}$/)
        .message("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%?&)")
        .required(),
    
    
}).required();

// Activate Account Schema
export const activateSchema = joi.object({
    activationCode: joi.string()
        .length(6)
        .pattern(/^\d+$/)
        .message("Activation code must be a 6-digit number")
        .required()
}).required();

// Login Schema
export const loginSchema = joi.object({
    email: joi.string()
        .email()
        .required(),
    password: joi.string()
        .required()
}).required();

// Forget Password Schema
export const forgetCodeSchema = joi.object({
    email: joi.string()
        .email()
        .required()
}).required();

// Reset Password Schema
export const resetPassSchema = joi.object({
    email: joi.string()
        .email()
        .required(),
    forgetCode: joi.string()
        .length(5)
        .pattern(/^\d+$/)
        .message("Reset code must be a 6-digit number")
        .required(),
        password: joi.string()
        .min(8)
        .max(32)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%?&]).{8,32}$/)
        .message("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%?&)")
        .required(),
    confirmPassword: joi.string()
        .valid(joi.ref('password'))
        .required()
        .messages({ "any.only": "Passwords must match" })
}).required();