import mongoose, { Schema, model } from 'mongoose';
import { Types } from 'mongoose';

// Message Schema
const messageSchema = new Schema({
  sender: { 
    type: Types.ObjectId, 
    ref: 'User', 
    required: [true, 'Sender is required'], // Validation for sender
  },
  receiver: { 
    type: Types.ObjectId, 
    ref: 'User', 
    required: [true, 'Receiver is required'], // Validation for receiver
  },
  content: { 
    type: String, 
    required: [true, 'Content cannot be empty'], // Validation for content
    minlength: [1, 'Message content must be at least 1 character long'], // Optional: Minimum length for content
  },
  read: { 
    type: Boolean, 
    default: false, 
  },
  timestamp: { 
    type: Date, 
    default: Date.now, 
  },
}, { timestamps: true });

// Creating the Message model
export const Message = mongoose.models.Message || model('Message', messageSchema);
