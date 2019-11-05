export { default as CognitoAuthenticator } from './authentication';
export { configureCognito, getAuthenticator, getRawUser } from './configuration';

import CognitoIdentity from './identity';
export default CognitoIdentity;
