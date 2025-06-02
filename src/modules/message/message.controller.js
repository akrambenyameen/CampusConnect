// controllers/messageController.js
import { User } from '../../../DB/models/user.model.js';  // Adjust the path according to your structure
import { Message } from '../../../DB/models/message.model.js';  // Adjust the path according to your structure
import mongoose from 'mongoose';

export const sendMessage = async (req, res) => {
  const { senderEmail, receiverEmail, content } = req.body;

  try {
    const sender = await User.findOne({ email: senderEmail });
    const receiver = await User.findOne({ email: receiverEmail });

    if (!sender || !receiver) return res.status(404).json({ error: "User not found" });

    // Validate message content (optional extra check)
    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: "Message content is required" });
    }

    const message = await Message.create({
      sender: sender._id,
      receiver: receiver._id,
      content,
    });

    res.status(201).json(message);
  } catch (err) {
    // Handle any validation or other errors
    if (err.name === 'ValidationError') {
      return res.status(400).json({ error: err.message });
    }
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};



export const GetMessage = async (req, res) => {
  const { user1, user2 } = req.params;

  try {
    // Fetch all messages between the two users
    const messages = await Message.find({
      $or: [
        { sender: user1, receiver: user2 },
        { sender: user2, receiver: user1 }
      ]
    })
      .sort({ timestamp: 1 })
      .populate('sender', 'name')
      .populate('receiver', 'name')
      .select('content timestamp read sender receiver');

    // Update unread messages to read
    await Message.updateMany(
      {
        sender: user2, // Only mark messages sent to the current user
        receiver: user1,
        read: false
      },
      { $set: { read: true } }
    );

    const responseMessages = messages.map(message => ({
      senderName: message.sender.name,
      receiverName: message.receiver.name,
      content: message.content,
      timestamp: message.timestamp,
      status: message.read ? 'read' : 'unread'
    }));

    res.json(responseMessages);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to retrieve messages' });
  }
};




  

export const GetChatsOverview = async (req, res) => {
  try {
    const currentUserId = req.user._id;

    const messages = await Message.aggregate([
      {
        $match: {
          $or: [
            { sender: new mongoose.Types.ObjectId(currentUserId) },
            { receiver: new mongoose.Types.ObjectId(currentUserId) }
          ]
        }
      },
      {
        $project: {
          sender: 1,
          receiver: 1,
          content: 1,
          timestamp: 1,
          read: 1,
          otherUser: {
            $cond: [
              { $eq: ['$sender', new mongoose.Types.ObjectId(currentUserId)] },
              '$receiver',
              '$sender'
            ]
          }
        }
      },
      {
        $sort: { timestamp: -1 }
      },
      {
        $group: {
          _id: '$otherUser',
          lastMessage: { $first: '$content' },
          timestamp: { $first: '$timestamp' },
          read: { $first: '$read' }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$_id',
          name: '$user.name',
          lastMessage: 1,
          timestamp: 1,
          status: {
            $cond: [{ $eq: ['$read', true] }, 'read', 'unread']
          }
        }
      }
    ]);

    res.json(messages);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to load chats overview' });
  }
};

  


