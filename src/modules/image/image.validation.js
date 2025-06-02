import Joi from "joi";

// Upload Image Schema
export const uploadImageSchema = Joi.object({
    apartment_id: Joi.string()
        .length(24) // MongoDB ObjectId length
        .hex()
        .required()
        .messages({
            "any.required": "Apartment ID is required",
            "string.empty": "Apartment ID cannot be empty",
            "string.length": "Invalid Apartment ID format",
            "string.hex": "Apartment ID must be a valid ObjectId",
        }),
}).required();

import joi from "joi";

export const imageIdSchema = joi.object({
    id: joi.string()
        .regex(/^[0-9a-fA-F]{24}$/) // MongoDB ObjectId format
        .message("Invalid ID format")
        .required()
});

