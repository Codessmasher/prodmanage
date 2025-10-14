import { Router } from "express";
import { registerUser, loginUser } from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validator.middleware.js";
import {userRegisterValidator} from "../validators/validator.js" 

const router = Router();

// Register Route
router.post("/register", userRegisterValidator(),validate, registerUser);
// Login Route
router.post("/login", loginUser);
 

export default router;
