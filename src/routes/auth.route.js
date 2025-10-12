import { Router } from "express";
import { registerUser } from "../controllers/auth.controller.js";
 

const router = Router();

// unsecured route
router.post("/register", registerUser);
 

export default router;
