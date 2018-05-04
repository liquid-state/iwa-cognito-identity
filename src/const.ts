export const LOGIN_RESPONSE_SUCCESS = 1;
export const LOGIN_RESPONSE_ERROR = 2;
export const LOGIN_RESPONSE_MFA_REQUIRED = 3;
export const LOGIN_RESPONSE_CHANGE_PASSWORD = 4;

export const REGISTRATION_SUCCESS = 0;
export const REGISTRATION_INVALID_USERNAME = 1;
export const REGISTRATION_USERNAME_EXISTS = 2;
export const REGISTRATION_INVALID_PASSWORD = 3;
export const REGISTRATION_INVALID_PHONE_NUMBER = 4;
export const REGISTRATION_PHONE_NUMBER_EXISTS = 5;
// For handling cases where we do not recognise the failure mode.
export const REGISTRATION_FAILURE_GENERIC = 100;
