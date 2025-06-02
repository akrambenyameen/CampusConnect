// SavedApartment Schema
import mongoose, { Schema, model } from 'mongoose';
import { Types } from 'mongoose';

const savedApartmentSchema = new Schema({
    user: {
        type: Types.ObjectId,
        ref: 'User',
        required: true
    },
    apartment: {
        type: Types.ObjectId,
        ref: 'Apartment',
        required: true
    }
}, { timestamps: true });

export const SavedApartment = mongoose.models.SavedApartment || model('SavedApartment', savedApartmentSchema);
