import joi from "joi";
import { Types } from "mongoose";

export const isValid = (schema) => {
    return (req, res, next) => {
        const copyReq = { ...req.body, ...req.params, ...req.query };

        const validationResult = schema.validate(copyReq, {
            abortEarly: false, // Allows all errors to be reported
            allowUnknown: true // Ignores extra fields
        });

        if (validationResult.error) {
            const ErrorMessage = validationResult.error.details.map((error) => error.message);
            return next(new Error(ErrorMessage.join(", ")), { cause: 400 });
        }

        return next();
    };
};

export const isValidObjId = (value, helper) => {
    if (!Types.ObjectId.isValid(value)) {
        return helper.message("Invalid ObjectId");
    }
    return value; // Ensures proper continuation in validation
};