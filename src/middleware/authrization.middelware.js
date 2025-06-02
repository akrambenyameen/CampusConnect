import { asyncHandler } from '../utils/asynchandler.js';

export const isAuthorized = (roles) => {
    return asyncHandler(async (req, res, next) => {
        // Ensure user exists in request
        if (!req.user || !req.user.role) {
            return next(new Error("Unauthorized access"), { cause: 401 });
        }

        // Check if user role is authorized
        if (Array.isArray(roles)) {
            if (!roles.includes(req.user.role)) {
                return next(new Error("You are not authorized!"), { cause: 403 });
            }
        } else {
            if (roles !== req.user.role) {
                return next(new Error("You are not authorized!"), { cause: 403 });
            }
        }

        return next();
    });
};