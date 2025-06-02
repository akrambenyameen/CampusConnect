import { Router } from "express";
import { isValid } from "../../middleware/validation.middleware.js";
import { uploadImage,getImageById,deleteImage } from "./image.controller.js";
import { fileUpload, filterObject } from "../../utils/multer.js";
import { uploadImageSchema ,imageIdSchema } from "./image.validation.js";
import { isAuthorized } from "../../middleware/authrization.middelware.js";
import { isAuthenticated } from "../../middleware/authentication.middelware.js";

const router = Router();

// Upload Image
router.post(
    "/upload",isAuthenticated,isAuthorized(["renter"]),
    isValid(uploadImageSchema),
    fileUpload(filterObject.image).single("image"),
    uploadImage
);
//  Get Image by ID
router.get("/:id", isValid(imageIdSchema),getImageById);

//  Delete Image by ID
router.delete("/:id", isValid(imageIdSchema),deleteImage);
export default router;
