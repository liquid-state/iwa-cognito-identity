export { default as CognitoAuthenticator } from './authentication';
export { configureCognito, getAuthenticator } from './configuration';

import CognitoIdentity from './identity';
export default CognitoIdentity;
