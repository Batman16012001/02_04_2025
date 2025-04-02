const express = require("express");
const useridValidation = require("../controllers/useridValidationController");
const forgetPasswordController = require("../controllers/forgetPasswordController");
const generateOTP = require("../controllers/generateOTPController");
const validateOTP = require("../controllers/validateOTPController");
const loginController = require("../controllers/loginController");
const decryptionMiddleware = require("../decryptionService/decryptionMiddleware"); // Import the middleware

const router = express.Router();

// Apply the decryption middleware to specific routes
router.post("/login", decryptionMiddleware, loginController.login);

// Other routes without decryption middleware
router.get("/useridValidation/:user_id", useridValidation.useridValidation);
router.post("/generateOTP", generateOTP.generateOTP);
router.post("/validateOTP", validateOTP.validateOTPController);
router.post("/forgetPassword", forgetPasswordController.forgetPassword);

module.exports = router;