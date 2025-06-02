import Joi from "joi";

// Upload Image Schema
export const SaveApartmentSchema = Joi.object({
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