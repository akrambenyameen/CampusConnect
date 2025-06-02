import { asyncHandler } from './../utils/asynchandler.js'
import { Token } from './../../DB/models/token.model.js'
import { User } from './../../DB/models/user.model.js'
import jwt from 'jsonwebtoken'

export const isAuthenticated = asyncHandler(async (req, res, next) => {
    // Check if token exists in headers
    let token = req.headers["token"]
    if (!token) return next(new Error("Token required"), { cause: 400 });

    // Check if token starts with the correct BEARER_KEY
    if (!token.startsWith(process.env.BEARER_KEY)) {
        return next(new Error("Invalid token!"));
    }

    // Extract actual token from header
    token = token.split(process.env.BEARER_KEY)[1];

    // Verify token
    let decoded;
    try {
        decoded = jwt.verify(token, process.env.TOKEN_KEY);
    } catch (err) {
        return next(new Error("Invalid or expired token!"));
    }

    // Check if token exists in DB and is valid
    const tokenInDB = await Token.findOne({ token, isValid: true });
    if (!tokenInDB) return next(new Error("Token doesn't exist or is invalid!"));

    // Check if user exists using decoded.id instead of decoded.email
    const user = await User.findById(decoded.id);
    if (!user) return next(new Error("User not found!"));

    // Attach user to request object
    req.user = user;

    return next();
});