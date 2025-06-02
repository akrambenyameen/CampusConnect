import authRouter from './modules/user/user.router.js';
import imageRouter from './modules/image/image.router.js';
import apartmentRoutes from './modules/apartment/apartment.router.js';
import imageRoutes from './modules/image/image.router.js';
import router from './modules/SavedApartments/SavedApartments.router.js';
import MessageRouter from './modules/message/message.router.js'

export const appRouter = (app, express) => {
    // Global Middleware
    app.use(express.json());
    app.use(express.urlencoded({ extended: true })); // Support form data

    // ROUTES
    app.use("/auth", authRouter);
    app.use("/image",imageRouter)
    app.use('/api/apartments', apartmentRoutes);
    app.use('/saved',router)
    app.use("/message",MessageRouter)

    // Handle 404 Not Found
    app.all("*", (req, res, next) => {
        const error = new Error("Page not found!");
        error.cause = 404;
        return next(error);
    });

    // Handle JSON Parsing Errors
    app.use((err, req, res, next) => {
        if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
            return res.status(400).json({
                success: false,
                message: "Invalid JSON format",
            });
        }
        next(err);
    });

    // Global Error Handler
    app.use((error, req, res, next) => {
        return res.status(error.cause || 500).json({
            success: false,
            message: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    });
};