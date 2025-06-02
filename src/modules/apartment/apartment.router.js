import { Router } from "express";
import { addApartment, getApartments, getApartmentById, updateApartment, deleteApartment ,searchApartmentByCity} from "./apartment.controller.js";
import { apartmentValidation } from "../apartment/apartment.validation.js";
import Joi from "joi"; 
import { isValid } from "../../middleware/validation.middleware.js";
import { fileUpload } from "../../utils/multer.js"; // Import multer
import { filterObject } from "../../utils/multer.js";
import { isAuthenticated } from "../../middleware/authentication.middelware.js";
import { isAuthorized } from "../../middleware/authrization.middelware.js";

const router = Router();

// ✅ Add `fileUpload("image")` before `isValid`
router.post("/addApartment", isAuthenticated ,isAuthorized(["renter"]), fileUpload(filterObject.image).single("image"), isValid(apartmentValidation), addApartment);
router.get("/getApartments",isAuthenticated, getApartments);
router.get("/getApartmentById/:id", isAuthenticated,getApartmentById);
router.put("/updateApartment/:id", isAuthenticated,isAuthorized(["renter"]),updateApartment);
router.delete("/deleteApartment/:id", isAuthenticated,isAuthorized(["renter"]),deleteApartment);
router.get("/SearchByCity",isAuthenticated, searchApartmentByCity);



export default router;
