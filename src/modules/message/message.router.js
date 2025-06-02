// routes/messageRoutes.js
import express from 'express';
import { sendMessage,GetMessage,GetChatsOverview } from '../message/message.controller.js';  // Adjust the path according to your structure
import { isAuthenticated } from '../../middleware/authentication.middelware.js';

const MessageRouter = express.Router();

// POST route for sending a message
MessageRouter.post('/send', isAuthenticated,sendMessage);
MessageRouter.get('/chat/:user1/:user2',isAuthenticated,GetMessage)
MessageRouter.get('/messages/:id',isAuthenticated,GetChatsOverview)


export default MessageRouter;
