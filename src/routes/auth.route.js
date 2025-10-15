import { Router } from "express";
import {
    registerUser,
    loginUser,
    resendVerificationLink,
    logoutUser,
    getCurrentUser,
    verifyEmail,
    refreshAccessToken,
    forgotPasswordRequest,
    resetForgotPassword,
    changeCurrentPassword
} from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validator.middleware.js";
import {
    userRegisterValidator,
    userLoginValidator,
    userChangeCurrentPasswordValidator,
    userForgotPasswordValidator,
    userResetForgotPasswordValidator,
} from "../validators/validator.js"
import { verifyJWT } from "../middlewares/auth.middleware.js"

const router = Router();


/*------ Unsecured Routes ---------*/

// Register Route
router.post("/register", userRegisterValidator(), validate, registerUser);
// Login Route
router.post("/login", userLoginValidator(), validate, loginUser);
// Email Verification Route
router.get("/verify-email/:verificationToken", verifyEmail);
// Refresh Access Token Route
router.post("/refresh-token", refreshAccessToken);
// Forgot Password Routes
router.post("/forgot-password", userForgotPasswordValidator(), validate, forgotPasswordRequest);
// Reset Forgot Password Route
router.post("/reset-password/:resetToken", userResetForgotPasswordValidator(), validate, resetForgotPassword);



/*------ Secured Routes ---------*/

// Logout Route
router.post("/logout", verifyJWT, logoutUser);
// Get Current User Route
router.get("/current-user", verifyJWT, getCurrentUser);
// Resend Email Verification Link Route
router.post("/send-verification-link", verifyJWT, resendVerificationLink);
// Change Current Password Route
router.post("/change-password", verifyJWT, userChangeCurrentPasswordValidator(), validate, changeCurrentPassword);


export default router;
