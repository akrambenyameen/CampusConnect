import { SavedApartment } from './../../../DB/models/SavedApartment.model.js';
import { Apartment } from './../../../DB/models/apartment.model.js';


export const toggleSaveApartment = async (req, res) => {
    try {
        const { apartmentId } = req.params;
        const userId = req.user._id;

        // Check if apartment exists
        const apartment = await Apartment.findById(apartmentId);
        if (!apartment) {
            return res.status(404).json({ message: "Apartment not found" });
        }

        // Check if already saved
        const existingSave = await SavedApartment.findOne({
            user: userId,
            apartment: apartmentId
        });

        if (existingSave) {
            // If saved → unsave it (remove from collection)
            await SavedApartment.findByIdAndDelete(existingSave._id);
            return res.status(200).json({ message: "Apartment unsaved successfully" });
        } else {
            // If not saved → save it
            const newSave = await SavedApartment.create({
                user: userId,
                apartment: apartmentId
            });
            return res.status(201).json({ message: "Apartment saved successfully", saved: newSave });
        }
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
};




export const getAllSavedApartments = async (req, res) => {
    try {
        const userId = req.user._id;

        const savedApartments = await SavedApartment.aggregate([
            {
                $match: { user: userId }
            },
            {
                $lookup: {
                    from: 'apartments',
                    localField: 'apartment',
                    foreignField: '_id',
                    as: 'apartment'
                }
            },
            {
                $unwind: '$apartment'
            },
            {
                $lookup: {
                    from: 'images',
                    localField: 'apartment._id',
                    foreignField: 'apartment_id',
                    as: 'apartment.images'
                }
            },
            {
                $project: {
                    _id: 0,
                    apartment: 1
                }
            }
        ]);

        return res.status(200).json({
            message: "Saved apartments with images fetched successfully",
            count: savedApartments.length,
            savedApartments
        });
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
};


  
export const searchSavedApartmentByCity = async (req, res) => {
    try {
        const { city } = req.query;

        if (!city) {
            return res.status(400).json({ error: "City query is required" });
        }

        // Search for saved apartments that match the city
        const savedApartments = await SavedApartment.aggregate([
            {
                $lookup: {
                    from: "apartments",  // Use the apartments collection for the reference
                    localField: "apartment",  // Field in SavedApartment referencing Apartment _id
                    foreignField: "_id",  // Match with Apartment _id
                    as: "apartment"  // Create a new field with apartment details
                }
            },
            {
                $unwind: "$apartment"  // Unwind the apartment array to flatten the documents
            },
            {
                $match: {
                    "apartment.city": { $regex: city, $options: 'i' }  // Case-insensitive search for city
                }
            },
            {
                $lookup: {
                    from: "images",  // Lookup for images collection
                    localField: "apartment._id",  // Reference to apartment _id
                    foreignField: "apartment_id",  // Reference in images collection
                    as: "images"  // Add images to the result
                }
            }
        ]);

        if (savedApartments.length === 0) {
            return res.status(404).json({ message: "No saved apartments found in the specified city" });
        }

        res.status(200).json({ savedApartments });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

