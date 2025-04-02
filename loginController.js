const Ajv = require('ajv');
const ajvFormats = require('ajv-formats');
const validateSchema = require('../validatorsJSON/loginSchema.json');
const loginService = require("../services/loginService");
const errors = require('../error');
const DecryptionService = require('../decryptionService/decryptionService');

const ajv = new Ajv({ allErrors: true });
ajvFormats(ajv);

// Initialize the decryption service
const decryptionService = new DecryptionService();

exports.login = async (req, res, next) => {
    try {
        console.log("Received login request body:", JSON.stringify(req.body));

        // Check if the request contains encrypted login credentials
        if (req.body.login_creds) {
            try {
                // Decrypt the login credentials
                const decryptedData = await decryptionService.decrypt(req.body.login_creds);
                console.log("Successfully decrypted login credentials");

                // Replace the encrypted data with the decrypted data
                req.body = decryptedData;
            } catch (decryptError) {
                console.error("Decryption error:", decryptError.message);
                const error = errors.InvalidDataFormat || {
                    statusCode: 400,
                    errorCode: "INVALID_DATA_FORMAT",
                    message: "Invalid encrypted data format",
                    details: "The provided encrypted data could not be decrypted"
                };

                return res.status(error.statusCode).json({
                    errorCode: error.errorCode,
                    message: error.message,
                    details: `Decryption failed: ${decryptError.message}`
                });
            }
        }

        // Proceed with validation of the decrypted data
        const valid = ajv.validate(validateSchema, req.body);

        if (!valid) {
            console.log("Validation Errors: " + JSON.stringify(ajv.errors));

            const missingFields = ajv.errors
                .filter(error => error.keyword === 'required')
                .map(error => error.params.missingProperty);

            if (missingFields.length > 0) {
                const error = errors.MissingRequiredFields;
                return res.status(error.statusCode).json({
                    errorCode: error.errorCode,
                    message: `The following fields are missing: ${missingFields.join(', ')}`,
                    details: error.details
                });
            }

            const validationErrors = ajv.errors.map(error => {
                let parameter = error.instancePath.substr(1);
                parameter = parameter.split('/').pop();
                return {
                    parameter: parameter,
                    message: `${parameter} parameter ${error.message}`
                };
            });

            const invalidFields = validationErrors.map(err => err.parameter);

            console.log("Validation Errors with parameters: " + JSON.stringify(validationErrors));
            const error = errors.InvalidDataFormat;
            return res.status(error.statusCode).json({
                errorCode: error.errorCode,
                message: `The provided input seems to be invalid: ${invalidFields.join(', ')}.`,
                details: validationErrors.map(err => err.message)
            });
        }

        const { user_id: userId, password } = req.body;

        const loginReq = await loginService.login(userId, password);

        if (typeof loginReq === 'string') {
            const [errorCode, userId] = loginReq.split(': ');
            const error = errors[errorCode];
            return res.status(error.statusCode).json({
                errorCode: error.errorCode,
                message: error.message.replace('{userId}', userId),
                details: error.details
            });
        }

        return res.status(201).json(loginReq);

    } catch (error) {
        console.log("Error in login Controller :" + JSON.stringify(error.message));
        const internalError = errors.InternalServerError;
        return res.status(internalError.statusCode).json({
            errorCode: internalError.errorCode,
            message: internalError.message,
            details: internalError.details
        });
    }
};