import * as codes from './const';

export type AuthenticationCodes =
  | typeof codes.LOGIN_RESPONSE_SUCCESS
  | typeof codes.LOGIN_RESPONSE_ERROR
  | typeof codes.LOGIN_RESPONSE_MFA_REQUIRED
  | typeof codes.LOGIN_RESPONSE_CHANGE_PASSWORD;

export type RegistrationCodes =
  | typeof codes.REGISTRATION_SUCCESS
  | typeof codes.REGISTRATION_INVALID_USERNAME
  | typeof codes.REGISTRATION_USERNAME_EXISTS
  | typeof codes.REGISTRATION_INVALID_PASSWORD
  | typeof codes.REGISTRATION_INVALID_PHONE_NUMBER
  | typeof codes.REGISTRATION_PHONE_NUMBER_EXISTS
  | typeof codes.REGISTRATION_FAILURE_GENERIC;

export interface LoginResponse {
  code: AuthenticationCodes;
  [key: string]: any;
}

export interface RegistrationResponse {
  code: RegistrationCodes;
  [key: string]: any;
}

export interface IAuthenticationService {
  login: (credentials: object) => Promise<LoginResponse>;
  completeChangePassword: (newPassword: string) => Promise<any>;
  register: (userData: object) => Promise<RegistrationResponse>;
  resendRegistrationCode: () => Promise<any>;
  confirmRegistration: (code: string, forUsername?: string) => Promise<any>;
  validateMFAToken: (token: string) => Promise<any>;
  beginResetPassword: (username: string) => Promise<any>;
  completeResetPassword: (validationCode: string, newPassword: string) => Promise<any>;
  enableMFA: () => Promise<any>;
  disableMFA: () => Promise<any>;
  userChangePassword: (oldPassword: string, newPassword: string) => Promise<any>;
}
