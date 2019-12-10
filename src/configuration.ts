import { CognitoUserPool, CognitoUser } from 'amazon-cognito-identity-js';
import { Key } from '@liquid-state/iwa-keyvalue';
import IdentityPlugin from '@liquid-state/iwa-identity';
import CognitoIdentity, { AWSIdentity } from './identity';
import CognitoAuthenticator from './authentication';
import { IApp } from '@liquid-state/iwa-core/dist/app/app';

const COGNITO_SETTINGS = ['AWS_USER_POOL_ID', 'AWS_USER_POOL_CLIENT_ID'];

export type setPermissionsForKeyT = (key: Key) => Key;

export const configureCognito = async (app: IApp, _: setPermissionsForKeyT) => {
  const settings = await app.configuration(...COGNITO_SETTINGS);

  const { AWS_USER_POOL_ID, AWS_USER_POOL_CLIENT_ID } = settings;

  const userPool = new CognitoUserPool({
    UserPoolId: AWS_USER_POOL_ID,
    ClientId: AWS_USER_POOL_CLIENT_ID,
  });

  app.use(IdentityPlugin).addProvider('cognito', new CognitoIdentity(userPool));
};

export const getAuthenticator = async (app: IApp) => {
  const settings = await app.configuration(...COGNITO_SETTINGS);
  const userPool = new CognitoUserPool({
    UserPoolId: settings.AWS_USER_POOL_ID,
    ClientId: settings.AWS_USER_POOL_CLIENT_ID,
  });
  const idp = await app.use(IdentityPlugin);
  const identity = await idp.forService('cognito').getIdentity();
  if (identity.isAuthenticated) {
    return CognitoAuthenticator.fromIdentity(userPool, identity as AWSIdentity);
  }
  return new CognitoAuthenticator(userPool);
};

export const getRawUser = async (app: IApp): Promise<CognitoUser | null> => {
  const settings = await app.configuration(...COGNITO_SETTINGS);
  const { AWS_USER_POOL_ID, AWS_USER_POOL_CLIENT_ID } = settings;
  const userPool = new CognitoUserPool({
    UserPoolId: AWS_USER_POOL_ID,
    ClientId: AWS_USER_POOL_CLIENT_ID,
  });
  return userPool.getCurrentUser();
};
