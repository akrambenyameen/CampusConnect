// savedApartment.router.js
import { Router } from 'express';
import { searchSavedApartmentByCity, toggleSaveApartment } from './SavedApartments.controller.js';
import { isAuthenticated } from '../../middleware/authentication.middelware.js';
import { isAuthorized } from '../../middleware/authrization.middelware.js';
import { isValid } from '../../middleware/validation.middleware.js';
import { SaveApartmentSchema } from './SavedApartments.validation.js';
import { getAllSavedApartments } from './SavedApartments.controller.js';


const router = Router();

router.post('/toggle/:apartmentId', isAuthenticated, toggleSaveApartment);
router.get('/all', isAuthenticated, getAllSavedApartments);
router.get('/SearchSavedApartmentByCity', isAuthenticated, searchSavedApartmentByCity);




export default router;
