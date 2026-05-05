import { body } from "express-validator";

const enterprisePasswordRegex =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d])[A-Za-z\d^$*.[\]{}()?"!@#%&/\\,><':;|_~`+=-]{12,128}$/;

const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .matches(enterprisePasswordRegex)
      .withMessage(
        "Password must be 12-128 chars and include uppercase, lowercase, number, and special character",
      ),
  ];
};

const userLoginValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
    body("password").notEmpty().withMessage("Password is required"),
  ];
};

export {
    userRegisterValidator,
    userLoginValidator
}