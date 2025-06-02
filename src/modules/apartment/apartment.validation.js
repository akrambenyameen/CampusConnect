// validations/apartmentValidation.js
import Joi from 'joi';

export const apartmentValidation = Joi.object({
    address: Joi.string().required(),
    description: Joi.string().allow(''),
    noOfRooms: Joi.number().required(),
    area: Joi.number().required(),
    price: Joi.number().required(),
    availability: Joi.boolean().default(true),
    city: Joi.string().required(),
    country: Joi.string().required(),
    user_id: Joi.string().required()
});