import multer, { memoryStorage } from "multer";

export const filterObject = {
    image: ["image/png", "image/jpeg", "image/jpg"],
    file: ["application/pdf", "application/msword"],
    video: ["video/mp4"]
};

// 🛠 Fix: Use filterArray instead of undefined filetype
export const fileUpload = (filterArray) => {
    const fileFilter = (req, file, cb) => {
        if (!filterArray.includes(file.mimetype)) {  // ✅ Use filterArray
            return cb(new Error("Invalid format"), false);
        }
        return cb(null, true);
    };

    const multerUpload = multer({ storage: memoryStorage({}), fileFilter });

    return multerUpload;
};
