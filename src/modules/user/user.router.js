import { Router } from "express"
import { isValid } from "./../../middleware/validation.middleware.js"
import { registerSchema, activateSchema, loginSchema, forgetCodeSchema, resetPassSchema } from "./user.validation.js"
import { register, activateAcc, login, forgetCode, resetPassword } from "./user.controller.js"

const router = Router()
// register
router.post("/register", isValid(registerSchema), register)

//activate account
router.get("/confirmEmail/:activationCode", isValid(activateSchema), activateAcc)

//login
router.post("/login", isValid(loginSchema), login)

//send forget code 
router.patch("/forgetCode", isValid(forgetCodeSchema), forgetCode)

//reset password
router.patch("/resetPassword", isValid(resetPassSchema), resetPassword)

export default router

