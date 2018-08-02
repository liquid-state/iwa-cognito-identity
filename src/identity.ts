import * as AWS from 'aws-sdk/global';
import { CognitoIdentityCredentials } from 'aws-sdk';

import {
  CognitoUserSession,
  CognitoUserPool,
  CognitoUser,
  CognitoIdToken,
  CognitoAccessToken,
  CognitoRefreshToken,
} from 'amazon-cognito-identity-js';

import { IIdentity } from '@liquid-state/iwa-identity/dist/identity';
import { IIdentityProvider } from '@liquid-state/iwa-identity/dist/manager';
import { IIdentityStore, ISerialisableIdentity } from '@liquid-state/iwa-identity/dist/store';

import { Identity } from '@liquid-state/iwa-identity';

export type AWSServiceCredentials = {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
};

/**
 * An aws specific identity which returns valid credentials based on the awsCredentialsProvider.
 * The awsCredentialsProvider is supplied as a thunk so that if the provider changes credentials,
 * those changes are made available to the identity
 */
export class AWSIdentity implements IIdentity<AWSServiceCredentials> {
  public isAuthenticated: boolean;
  public name: string;

  private identityMap = new Map<string, string>();
  private credentialsProvider: () => any;

  constructor(name: string, awsCredentialsProviderFn: any) {
    this.name = name;
    this.credentialsProvider = awsCredentialsProviderFn;

    this.isAuthenticated = Boolean(name);
  }

  get credentials() {
    let credsProvider = this.credentialsProvider();
    return {
      accessKeyId: credsProvider.accessKeyId,
      secretAccessKey: credsProvider.secretAccessKey,
      sessionToken: credsProvider.sessionToken,
    };
  }

  get identifiers() {
    if (!this.identityMap.has('sub')) {
      const creds = this.credentialsProvider();
      this.identityMap.set('sub', creds.identityId);
    }
    return this.identityMap;
  }
}

export default class CognitoIdentityProvider implements IIdentityProvider<AWSServiceCredentials> {
  private identity: IIdentity<AWSServiceCredentials> = new Identity(null, null);
  private session: CognitoUserSession | null;

  private credentialsProvider: CognitoIdentityCredentials | undefined;

  constructor(
    private userPool: CognitoUserPool,
    private identityPoolId: string,
    private store: IIdentityStore,
    private storeKey = 'cognito'
  ) {}

  async getIdentity() {
    const storedIdentity = await this.store.fetch(this.storeKey);
    if (this.identity.name && storedIdentity.identity !== this.identity.name) {
      this.identity = new Identity(null, null);
      this.session = null;
    }
    if (!this.session) {
      await this.restoreSession(storedIdentity);
    }
    if (this.session && !this.session.isValid()) {
      try {
        await this.refreshExpiredSession();
      } catch (e) {
        this.identity = new Identity(null, null);
        return this.identity;
      }
    }
    if (!this.credentialsProvider) {
      this.configureAWSCredentials();
    }
    if (this.credentialsProvider && this.credentialsProvider.needsRefresh()) {
      try {
        await this.refreshAWSCredentials();
      } catch (e) {
        this.identity = new Identity(null, null);
      }
    }
    return this.identity;
  }

  async update(name: string, credentials: any, store = true) {
    this.identity = new AWSIdentity(name, () => this.credentialsProvider);
    this.session = new CognitoUserSession({
      IdToken: credentials.idToken,
      AccessToken: credentials.accessToken,
      RefreshToken: credentials.refreshToken,
    });
    await this.configureAWSCredentials();
    await this.refreshAWSCredentials();
    if (store) {
      this.store.store(this.storeKey, { identity: name, credentials });
    }
    return this.identity;
  }

  async clear() {
    this.session = null;
    // This is needed to remove the IdentityId from the aws credentials provider
    // This appears to be maintained across objects even when the provider has been disposed.
    new CognitoIdentityCredentials({ IdentityPoolId: this.identityPoolId }).clearCachedId();
    this.credentialsProvider = undefined;
    AWS.config.credentials = undefined;

    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key) continue;
      if (
        key.indexOf('CognitoIdentityServiceProvider') === 0 ||
        key.indexOf('aws.cognito') === 0
      ) {
        keysToRemove.push(key);
      }
    }
    for (let j = 0, key; (key = keysToRemove[j]); j++) {
      localStorage.removeItem(key);
    }

    this.store.store(this.storeKey, { identity: null, credentials: null });
  }

  private async restoreSession(storedIdentity: ISerialisableIdentity) {
    let { identity, credentials } = storedIdentity;
    if (!identity || !credentials) {
      return;
    }
    this.session = this.createUserSession(credentials);
    // Restore identity.
    // Note that credentials provider is not configured yet
    this.identity = new AWSIdentity(identity, () => this.credentialsProvider);
  }

  private createUserSession(credentials: any): CognitoUserSession {
    return new CognitoUserSession({
      IdToken: new CognitoIdToken({ IdToken: credentials.idToken.jwtToken }),
      AccessToken: new CognitoAccessToken({ AccessToken: credentials.accessToken.jwtToken }),
      RefreshToken: new CognitoRefreshToken({ RefreshToken: credentials.refreshToken.token }),
    });
  }

  private async refreshExpiredSession() {
    const user = new CognitoUser({
      Username: this.identity.name!,
      Pool: this.userPool,
    });
    return new Promise((resolve, reject) => {
      user.refreshSession(
        this.session!.getRefreshToken(),
        (err: any, session?: CognitoUserSession) => {
          if (err) {
            if (err.code === 'NetworkingError') {
              // Offline just rely on the refreshToken for now.
              resolve();
              return;
            }
            reject();
          } else {
            // If there is no error, the session is valid.
            this.session = session!;
            resolve();
          }
        }
      );
    });
  }

  private configureAWSCredentials() {
    if (!this.session) {
      return;
    }
    this.credentialsProvider = new CognitoIdentityCredentials({
      IdentityPoolId: this.identityPoolId,
      Logins: {
        [`cognito-idp.${
          AWS.config.region
        }.amazonaws.com/${this.userPool.getUserPoolId()}`]: this.session
          .getIdToken()
          .getJwtToken(),
      },
    });
    AWS.config.credentials = this.credentialsProvider;
  }

  private refreshAWSCredentials() {
    return new Promise((resolve, reject) => {
      if (!this.credentialsProvider) {
        reject();
        return;
      }
      this.credentialsProvider.refresh(err => {
        if (err) {
          reject(err);
        }
        resolve();
      });
    });
  }
}
