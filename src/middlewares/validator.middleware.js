import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";

export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }  
   // Extract only the messages
  const messages = errors.array().map((err) => err.msg);
  // Send all messages as an array
  throw new ApiError(422, messages.join(", "), errors.array());
  
};
