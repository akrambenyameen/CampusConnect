import mongoose, { Schema, model } from 'mongoose';
import { Types } from 'mongoose';

const apartmentSchema = new Schema({
    address: { 
        type: String, required: true
    },
    description: {
        type: String
    },
    noOfRooms: { 
        type: Number, required: true
    },
    area: {
        type: Number, required: true
    },
    price: {
        type: Number, required: true 
    },
    availability: {
        type: Boolean, default: true
    },
    city: {
        type: String, required: true
    },
    country: {
        type: String, required: true
    },
    user_id: {
        type: Types.ObjectId, ref: 'User', required: true
    },
    location: { 
        type: String 
    },
    mapsLink: {
        type: String
    }
}, { timestamps: true });

export const Apartment = mongoose.models.Apartment || model('Apartment', apartmentSchema);
