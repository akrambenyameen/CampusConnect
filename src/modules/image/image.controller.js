import { Image } from "../../../DB/models/image.model.js";
import cloudinary from "../../utils/cloudnairy.js";

//upload image


export const uploadImage = async (req, res) => {
    try {
      // 🛠 Log the file to check if it's being processed

        if (!req.file) {
            return res.status(400).json({ message: "No file uploaded" });
        }

        const { apartment_id } = req.body;

        // Upload to Cloudinary using stream
        const uploadStream = cloudinary.uploader.upload_stream(
            { folder: "apartments" },
            async (error, cloudinaryResult) => {
                if (error) {
                    return res.status(500).json({ message: "Cloudinary upload failed", error });
                }

                try {
                    // Save Image URL to MongoDB
                    const newImage = new Image({
                        url: cloudinaryResult.secure_url,
                        apartment_id,
                    });

                    await newImage.save();
                    return res.status(201).json({ message: "Image uploaded successfully", image: newImage });
                } catch (dbError) {
                    return res.status(500).json({ message: "Database error", error: dbError });
                }
            }
        );

        // Send image buffer to Cloudinary
        uploadStream.end(req.file.buffer);

    } catch (error) {
        // If an error occurs before the stream callback, return an error response
        return res.status(500).json({ message: "Server error", error });
    }
};

// get image by id
export const getImageById = async (req, res, next) => {
    try {
        const image = await Image.findById(req.params.id);
        if (!image) return res.status(404).json({ message: "Image not found" });

        res.status(200).json({ success: true, image });
    } catch (error) {
        next(error);
    }
};

//delete image by id 
export const deleteImage = async (req, res, next) => {
    try {
        const image = await Image.findById(req.params.id);
        if (!image) return res.status(404).json({ message: "Image not found" });

        // Extract Cloudinary public ID
        const publicId = image.url.split("/").pop().split(".")[0];

        // Delete from Cloudinary
        await cloudinary.uploader.destroy(publicId);

        // Delete from Database
        await Image.findByIdAndDelete(req.params.id);

        res.status(200).json({ message: "Image deleted successfully" });
    } catch (error) {
        next(error);
    }
};
