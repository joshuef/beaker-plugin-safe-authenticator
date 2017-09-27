import crypto from 'crypto';
import client from '../src/ffi/authenticator';

/* eslint-disable import/prefer-default-export */
export const getRandomCredentials = () => (
  /* eslint-disable import/prefer-default-export */
  ({
    locator: crypto.randomBytes(32).toString('hex').slice(0, 15),
    secret: crypto.randomBytes(32).toString('hex').slice(0, 15),
    invite: crypto.randomBytes(10).toString('hex')
  })
);

export function to(promise) {
   return promise.then(data => {
      return [null, data];
   })
   .catch(err => [err]);
}

export const createRandomAccount = () => {
  const randomCredentials = getRandomCredentials();
  return client.createAccount(
    randomCredentials.locator,
    randomCredentials.secret,
    randomCredentials.invite
  )
    .then(() => randomCredentials);
};

export const clearAccount = () => (client.logout());
