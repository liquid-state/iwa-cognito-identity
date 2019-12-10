import { CognitoUserSession, CognitoUserPool, CognitoUser } from 'amazon-cognito-identity-js';

import { IIdentity } from '@liquid-state/iwa-identity/dist/identity';
import { IIdentityProvider } from '@liquid-state/iwa-identity/dist/manager';
// import { IIdentityStore } from '@liquid-state/iwa-identity/dist/store';

import { Identity } from '@liquid-state/iwa-identity';
// import KVStorage, { OpaqueObject } from './storage';

export type AWSServiceCredentials = {
  user: CognitoUser;
  session: CognitoUserSession;
};

/**
 * An aws specific identity which returns valid credentials from Cognito.
 */
export class AWSIdentity implements IIdentity<AWSServiceCredentials> {
  public isAuthenticated: boolean;
  private identityMap = new Map<string, string>();

  constructor(public name: string, public credentials: AWSServiceCredentials) {
    this.isAuthenticated = Boolean(name);
  }

  get identifiers() {
    if (!this.identityMap.has('sub')) {
      const sub = this.credentials.session.getIdToken().decodePayload().sub;

      this.identityMap.set('sub', sub);
      this.identityMap.set('username', this.credentials.user.getUsername());
      this.identityMap.set('jwt', this.credentials.session.getAccessToken().getJwtToken());
    }
    return this.identityMap;
  }
}

export default class CognitoIdentityProvider implements IIdentityProvider<AWSServiceCredentials> {
  constructor(private userPool: CognitoUserPool) {}

  async getIdentity() {
    const user = this.userPool.getCurrentUser();
    if (!user) {
      return new Identity(null, null);
    }
    try {
      const session = await this.getSession(user);
      return new AWSIdentity(user.getUsername(), { user, session });
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
    return this.getIdentity();
  }

  async clear() {
    const user = this.userPool.getCurrentUser();
    if (user) {
      user.signOut();
    }
  }

  private getSession(user: CognitoUser) {
    return new Promise<CognitoUserSession>((resolve, reject) => {
      user.getSession((err: any, session: CognitoUserSession) => {
        err ? reject(err) : resolve(session);
      });
    });
  }
}
