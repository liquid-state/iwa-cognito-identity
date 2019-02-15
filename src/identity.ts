import * as AWS from 'aws-sdk/global';
import { CognitoIdentityCredentials } from 'aws-sdk';

import { CognitoUserSession, CognitoUserPool, CognitoUser } from 'amazon-cognito-identity-js';

import { IIdentity } from '@liquid-state/iwa-identity/dist/identity';
import { IIdentityProvider } from '@liquid-state/iwa-identity/dist/manager';
import { IIdentityStore } from '@liquid-state/iwa-identity/dist/store';

import { Identity } from '@liquid-state/iwa-identity';
import KVStorage, { OpaqueObject } from './storage';

export type AWSServiceCredentials = {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
};

/**
 * An aws specific identity which returns valid credentials from Cognito.
 */
export class AWSIdentity implements IIdentity<AWSServiceCredentials> {
  public isAuthenticated: boolean;
  private identityMap = new Map<string, string>();

  constructor(public name: string, public credentials: CognitoIdentityCredentials) {
    this.isAuthenticated = Boolean(name);
  }

  get identifiers() {
    if (!this.identityMap.has('sub')) {
      this.identityMap.set('sub', this.credentials.identityId);
    }
    return this.identityMap;
  }
}

export default class CognitoIdentityProvider implements IIdentityProvider<AWSServiceCredentials> {
  constructor(
    private userPool: CognitoUserPool,
    private identityPoolId: string,
    private store: IIdentityStore<OpaqueObject>,
    private storeKey = 'cognito'
  ) {}

  private get loginMapId() {
    const {
      config: { region },
    } = AWS;
    return `cognito-idp.${region}.amazonaws.com/${this.userPool.getUserPoolId()}`;
  }

  async getIdentity() {
    const user = this.userPool.getCurrentUser();
    if (!user) {
      return new Identity(null, null);
    }
    try {
      const session = await this.getSession(user);
      const credentials = this.configureAWSCredentials(session);

      if (credentials.needsRefresh()) {
        await this.refreshAWSCredentials(credentials);
      }
      return new AWSIdentity(user.getUsername(), credentials);
    } catch (e) {
      console.log(e);
      return new Identity(null, null);
    }
  }

  async update(name: string, session: CognitoUserSession, store = true) {
    const user = new CognitoUser({
      Username: name,
      Pool: this.userPool,
    });
    // This will clear any existing sessions with this userpool and
    // update the currently stored tokens.
    user.setSignInUserSession(session);
    // Clear any cached credentials.
    AWS.config.credentials = undefined;
    return this.getIdentity();
  }

  async clear() {
    const user = this.userPool.getCurrentUser();
    if (user) {
      user.signOut();
    }
    AWS.config.credentials = undefined;
  }

  private getSession(user: CognitoUser) {
    return new Promise<CognitoUserSession>((resolve, reject) => {
      user.getSession((err: any, session: CognitoUserSession) => {
        err ? reject(err) : resolve(session);
      });
    });
  }

  private configureAWSCredentials(session: CognitoUserSession) {
    if (!AWS.config.credentials) {
      AWS.config.credentials = new CognitoIdentityCredentials({
        IdentityPoolId: this.identityPoolId,
        Logins: {},
      });
    }
    // See https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CognitoIdentityCredentials.html
    const credentials = AWS.config.credentials as CognitoIdentityCredentials;
    (credentials.params as any).Logins[this.loginMapId] = session.getIdToken().getJwtToken();
    return credentials;
  }

  private refreshAWSCredentials(credentials: CognitoIdentityCredentials) {
    return new Promise((resolve, reject) => {
      credentials.refresh(err => {
        err ? reject(err) : resolve();
      });
    });
  }
}
