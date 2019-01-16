import { IIdentityStore } from '@liquid-state/iwa-identity/dist/store';

type OpaqueObject = {
  [index: string]: any;
};

/** This is a cognito storage helper to store congito sessions in kv
 *
 * The cognito UserPool object can support a custom storage provider, which allows
 * overriding how the session details for the user are stored. This class provides
 * that interface and is used automatically by authentication and identity.
 *
 * Typically these interfaces do not support async workflows because localStorage
 * is not async. To get around this we implement a single additional method
 * `sync` which returns a promise which resolves when the data has been loaded
 * from kv into local memory. This should be called at the start of getIdentity
 */
class KVStorage {
  cache: OpaqueObject = {};

  constructor(private storeKey: string, private store: IIdentityStore<OpaqueObject>) {}

  getItem = (key: string) => {
    const result = Object.prototype.hasOwnProperty.call(this.cache, key)
      ? this.cache[key]
      : undefined;
    console.log('Accessing id cache key', key, result);
    return result;
  };

  setItem = (key: string, value: string) => {
    this.cache[key] = value;
    this.store.store(this.storeKey, this.cache);
  };

  removeItem = (key: string) => {
    if (key in this.cache) {
      delete this.cache[key];
    }
    this.store.store(this.storeKey, this.cache);
  };

  clear = () => {
    this.cache = {};
    this.store.store(this.storeKey, this.cache);
  };

  sync = async (): Promise<void> => {
    let cache;
    console.log('Updating ID cache');
    try {
      cache = await this.store.fetch(this.storeKey);
    } catch (e) {
      console.error('ERROR updating cache', e);
    }
    // Default if cache errors, or returns null.
    if (!cache) {
      cache = {};
    }
    console.log('New Id cache', cache);
    this.cache = cache;
  };
}

export default KVStorage;
export { OpaqueObject };
