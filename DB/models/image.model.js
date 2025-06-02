// Image Schema
import mongoose, { Schema, model } from 'mongoose'
import { Types } from 'mongoose'
const imageSchema = new Schema({
    url: {
        type: String,
        required: true
    },
    apartment_id: {
        type: Types.ObjectId,
        ref: 'Apartment',
        required: true
    }
}, { timestamps: true });
export const Image = mongoose.models.Image || model('Image', imageSchema);