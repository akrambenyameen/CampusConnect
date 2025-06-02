// controllers/apartmentController.js
import { Apartment } from '../../../DB/models/apartment.model.js';
import { Image } from '../../../DB/models/image.model.js';
import { v2 as cloudinary } from "cloudinary";
import mongoose from 'mongoose'



export const addApartment = async (req, res) => {
    try {
        // Check if the image file exists in the request
        if (!req.file) {
            return res.status(400).json({ message: "Image is required" });
        }

        // Extract location from the request body
        const { location } = req.body;

        // Generate the Google Maps link if location is provided
        const mapsUrl = location 
            ? `https://www.google.com/maps/dir/?api=1&destination=${encodeURIComponent(location)}`
            : null;

        // Upload the image to Cloudinary
        const cloudinaryUpload = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                { folder: "apartments" },
                (error, cloudinaryResult) => {
                    if (error) reject(error);
                    else resolve(cloudinaryResult);
                }
            );
            stream.end(req.file.buffer);
        });

        // Create a new apartment object
        const newApartment = new Apartment({
            ...req.body, // Spread all other fields
            mapsLink: mapsUrl // Set the maps link dynamically
        });

        // Save the apartment to the database
        await newApartment.save();

        // Save the image to the database
        const newImage = new Image({
            url: cloudinaryUpload.secure_url,
            apartment_id: newApartment._id
        });

        await newImage.save();

        return res.status(201).json({
            message: "Apartment and image added successfully",
            apartment: newApartment,
            image: newImage
        });

    } catch (error) {
        console.error("Error:", error);
        return res.status(500).json({ message: "Server error", error });
    }
};

export const getApartments = async (req, res) => {
    try {
        const apartments = await Apartment.aggregate([
            {
                $lookup: {
                    from: "images", 
                    localField: "_id", 
                    foreignField: "apartment_id", 
                    as: "images" 
                }
            }
        ]);
        res.status(200).json(apartments);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

export const getApartmentById = async (req, res) => {
    try {
        const apartment = await Apartment.aggregate([
            {
                $match: { _id: new mongoose.Types.ObjectId(req.params.id) } 
            },
            {
                $lookup: {
                    from: "images", 
                    localField: "_id", 
                    foreignField: "apartment_id", 
                    as: "images" 
                }
            }
        ]);

        if (!apartment.length) return res.status(404).json({ error: 'Apartment not found' });
        res.status(200).json(apartment);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

export const updateApartment = async (req, res) => {
    try {
        const updatedApartment = await Apartment.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.status(200).json(updatedApartment);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

export const deleteApartment = async (req, res) => {
    try {
        const apartment = await Apartment.findById(req.params.id);
        if (!apartment) return res.status(404).json({ error: 'Apartment not found' });

        await Image.deleteMany({ apartment_id: req.params.id });

        await Apartment.findByIdAndDelete(req.params.id);

        res.status(200).json({ message: "Apartment deleted successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

export const searchApartmentByCity = async (req, res) => {
    try {
        const { city } = req.query;

        if (!city) {
            return res.status(400).json({ error: "City query is required" });
        }

        // Partial match using regex (case-insensitive)
        const apartments = await Apartment.aggregate([
            {
                $match: {
                    city: { $regex: city, $options: 'i' }
                }
            },
            {
                $lookup: {
                    from: "images",  // Name of the collection where images are stored
                    localField: "_id", // Field in the Apartment collection
                    foreignField: "apartment_id", // Field in the Image collection
                    as: "images" // The field that will hold the related images
                }
            }
        ]);

        if (apartments.length === 0) {
            return res.status(404).json({ message: "No apartments found in the specified city" });
        }

        res.status(200).json({ apartments });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
