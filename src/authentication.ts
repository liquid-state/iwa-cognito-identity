import {
  IAuthenticationService,
  LoginResponse,
  RegistrationResponse,
  RegistrationCodes,
} from './types';

import {
  CognitoUser,
  CognitoUserPool,
  AuthenticationDetails,
  CognitoUserAttribute,
} from 'amazon-cognito-identity-js';

import {
  LOGIN_RESPONSE_SUCCESS,
  LOGIN_RESPONSE_CHANGE_PASSWORD,
  LOGIN_RESPONSE_ERROR,
  LOGIN_RESPONSE_MFA_REQUIRED,
  REGISTRATION_SUCCESS,
  REGISTRATION_INVALID_USERNAME,
  REGISTRATION_USERNAME_EXISTS,
  REGISTRATION_INVALID_PASSWORD,
  REGISTRATION_INVALID_PHONE_NUMBER,
  REGISTRATION_PHONE_NUMBER_EXISTS,
  REGISTRATION_FAILURE_GENERIC,
} from './const';
import { AWSIdentity } from './identity';

export default class CognitoAuthenticator implements IAuthenticationService {
  constructor(private userPool: CognitoUserPool, private user?: CognitoUser) {}

  static async fromIdentity(
    userPool: CognitoUserPool,
    identity: AWSIdentity
  ): Promise<CognitoAuthenticator> {
    return new CognitoAuthenticator(userPool, identity.credentials.user);
  }

  async login({ username, password }: { username: string; password: string }) {
    let user = await this.getUser(username);

    let authDetails = new AuthenticationDetails({
      Username: username,
      Password: password,
    });
    return new Promise<LoginResponse>((resolve, reject) => {
      user.authenticateUser(authDetails, {
        onSuccess: session =>
          resolve({
            code: LOGIN_RESPONSE_SUCCESS,
            credentials: session,
            identity: username,
          }),
        onFailure: err => {
          reject({
            code: LOGIN_RESPONSE_ERROR,
            error: err.code,
          });
        },
        mfaRequired: mfaDetails => {
          resolve({ code: LOGIN_RESPONSE_MFA_REQUIRED });
        },
        newPasswordRequired: (attribs, requiredAttribs) => {
          resolve({
            code: LOGIN_RESPONSE_CHANGE_PASSWORD,
            attribs,
            requiredAttribs,
          });
        },
      });
    });
  }

  async completeChangePassword(newPassword: string) {
    let user = await this.getUser();
    return new Promise((resolve, reject) => {
      user.completeNewPasswordChallenge(
        newPassword,
        {},
        {
          onSuccess: session =>
            resolve({
              code: LOGIN_RESPONSE_SUCCESS,
              credentials: session,
              identity: user.getUsername(),
            }),
          onFailure: ({ code }) => reject(code),
          mfaRequired: () => resolve({ code: LOGIN_RESPONSE_MFA_REQUIRED }),
        }
      );
    });
  }

  async register(userData: { [key: string]: any }) {
    const { username, password, email, phone, locale } = userData;

    let attributeList = [
      {
        Name: 'email',
        Value: email,
      },
      {
        Name: 'phone_number',
        Value: phone,
      },
    ].map(attrib => new CognitoUserAttribute(attrib));

    if (locale) {
      attributeList.push(
        new CognitoUserAttribute({
          Name: 'locale',
          Value: locale,
        })
      );
    }

    return new Promise<RegistrationResponse>((resolve, reject) => {
      this.userPool.signUp(username, password, attributeList, [], (err, result) => {
        if (err) {
          reject(this.mapRegistrationError(err as any));
          return;
        }
        // If there is not error, there is a result.
        result = result!;
        this.user = result.user;
        const response: RegistrationResponse = { code: REGISTRATION_SUCCESS, user: result.user };
        resolve(response);
      });
    });
  }

  async resendRegistrationCode() {
    const user = await this.getUser();
    return new Promise(resolve => {
      user.resendConfirmationCode(err => {
        if (err) {
          console.error(err);
        }
        resolve();
      });
    });
  }

  async confirmRegistration(code: string, forUsername?: string) {
    let user = await this.getUser(forUsername);
    return new Promise((resolve, reject) => {
      user.confirmRegistration(code, false, (error, result) => {
        if (error) {
          return reject(error);
        }
        return resolve(result);
      });
    });
  }

  async validateMFAToken(token: string): Promise<LoginResponse> {
    const user = await this.getUser();
    return new Promise<LoginResponse>((resolve, reject) => {
      user.sendMFACode(token, {
        onSuccess: session =>
          resolve({
            code: LOGIN_RESPONSE_SUCCESS,
            credentials: session,
            identity: user.getUsername(),
          }),
        onFailure: err => {
          reject({
            code: LOGIN_RESPONSE_ERROR,
            error: err.code,
          });
        },
      });
    });
  }

  async beginResetPassword(username: string): Promise<any> {
    const user = await this.getUser(username);
    return new Promise((resolve, reject) => {
      user.forgotPassword({
        onSuccess: resolve,
        onFailure: reject,
        inputVerificationCode: resolve,
      });
    });
  }

  async completeResetPassword(validationCode: string, newPassword: string) {
    const user = await this.getUser();
    return new Promise((resolve, reject) => {
      user.confirmPassword(validationCode, newPassword, {
        onSuccess: resolve,
        onFailure: reject,
      });
    });
  }

  async userChangePassword(oldPassword: string, newPassword: string) {
    const user = await this.getUser();

    return new Promise((resolve, reject) => {
      user.changePassword(oldPassword, newPassword, (err, data) => {
        if (err) {
          return reject(err);
        }
        return resolve(data);
      });
    });
  }

  async enableMFA() {
    const user = await this.getUser();
    return new Promise((resolve, reject) => {
      user.enableMFA((err, result) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(result);
      });
    });
  }

  async disableMFA() {
    const user = await this.getUser();
    return new Promise((resolve, reject) => {
      user.disableMFA((err, result) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(result);
      });
    });
  }

  private mapRegistrationError(error: { code: string; message: string }): RegistrationResponse {
    if (error.code === 'InvalidParameterException') {
      if (error.message.indexOf('email') !== -1) {
        return { code: REGISTRATION_INVALID_USERNAME };
      }
      if (error.message.indexOf('password') !== -1) {
        return { code: REGISTRATION_INVALID_PASSWORD };
      }
      if (error.message.indexOf('phone number') !== -1) {
        return { code: REGISTRATION_INVALID_PHONE_NUMBER };
      }
    }
    if (error.code === 'UsernameExistsException') {
      return { code: REGISTRATION_USERNAME_EXISTS };
    }
    return { code: REGISTRATION_FAILURE_GENERIC };
  }

  private async getUser(username = '') {
    if (!this.user || username) {
      this.user = new CognitoUser({
        Username: username,
        Pool: this.userPool,
      });
    }
    return this.user;
  }
}
