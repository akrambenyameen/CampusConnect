import mongoose, { Schema, model } from 'mongoose'
import { Types } from 'mongoose'
//schema
const tokenSchema = new Schema({
  token: {
    type: String,
    required: true,
  },
  user: {
    type: Types.ObjectId,
    ref: 'User'
  },
  isValid: {
    type: Boolean,
    default: true
  },
  agent: {
    type: String,

  },
  expiredAt: {
    type: String
  }
},

  { timestamps: true })
// model 
export const Token = mongoose.model.token || model('Token', tokenSchema)
