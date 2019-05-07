import * as AWS from 'aws-sdk/global';
import { CognitoUserPool } from 'amazon-cognito-identity-js';
import KeyValuePlugin, { Key } from '@liquid-state/iwa-keyvalue';
import IdentityPlugin, { IdentityStore } from '@liquid-state/iwa-identity';
import CognitoIdentity, { AWSIdentity } from './identity';
import CognitoAuthenticator from './authentication';
import { IApp } from '@liquid-state/iwa-core/dist/app/app';

const COGNITO_SETTINGS = [
  'AWS_USER_POOL_ID',
  'AWS_IDENTITY_POOL_ID',
  'AWS_USER_POOL_CLIENT_ID',
  'AWS_REGION',
];

export type setPermissionsForKeyT = (key: Key) => Key;

export const configureCognito = async (app: IApp, setPermissionsForKey: setPermissionsForKeyT) => {
  const settings = await app.configuration(...COGNITO_SETTINGS);

  const { AWS_USER_POOL_ID, AWS_USER_POOL_CLIENT_ID, AWS_IDENTITY_POOL_ID, AWS_REGION } = settings;

  AWS.config.update({ region: AWS_REGION });

  const userPool = new CognitoUserPool({
    UserPoolId: AWS_USER_POOL_ID,
    ClientId: AWS_USER_POOL_CLIENT_ID,
  });

  const kv = app.use(KeyValuePlugin);
  const idStore = new IdentityStore(kv, { setPermissionsForKey });

  app
    .use(IdentityPlugin)
    .addProvider('cognito', new CognitoIdentity(userPool, AWS_IDENTITY_POOL_ID, idStore));
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
