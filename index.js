// api/index.js

import express from 'express';
import dotenv from 'dotenv';
import serverless from 'serverless-http';
import { connectDB } from '../ecommerce/DB/connection.js';
import { appRouter } from '../src/app.router.js';

dotenv.config();

const app = express();

// Connect to DB
connectDB();

// Apply appRouter middleware (your routes, body parsers, etc.)
appRouter(app, express);

// Export as Vercel serverless function
export const handler = serverless(app);
export default handler;
