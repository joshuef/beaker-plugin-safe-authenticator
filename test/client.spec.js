/* eslint-disable no-underscore-dangle */
import should from 'should';
import crypto from 'crypto';
import i18n from 'i18n';
import client from '../src/ffi/authenticator';
import * as helper from './helper';
import CONST from '../src/constants';

describe('Client', () => {
  let randomCredentials = null;
  const encodedAuthUri = 'safe-auth:AAAAAAgMpeUAAAAAHgAAAAAAAABuZXQubWFpZHNhZmUuZXhh' +
  'bXBsZXMudGVzdC1hcHAAEAAAAAAAAABTQUZFIGV4YW1wbGUgQXBwEQAAAAAAAABNYWlkU2FmZS5uZXQgTHR' +
  'kLgEDAAAAAAAAAAoAAAAAAAAAX2Rvd25sb2FkcwUAAAAAAAAAAAAAAAEAAAACAAAAAwAAAAQAAAAHAAAAAA' +
  'AAAF9wdWJsaWMFAAAAAAAAAAAAAAABAAAAAgAAAAMAAAAEAAAACgAAAAAAAABfZG9jdW1lbnRzBQAAAAAAA' +
  'AAAAAAAAQAAAAIAAAADAAAABAAAAA==';
  const encodedUnRegisterAuthUri = 'safe-auth:AAAAAKfmUZgCAAAA';
  const encodedContUri = 'safe-auth:AAAAAGGCe2cBAAAAHgAAAAAAAABuZXQubWFpZHNhZmUuZXhhbX' +
  'BsZXMudGVzdC1hcHAAEAAAAAAAAABTQUZFIGV4YW1wbGUgQXBwEQAAAAAAAABNYWlkU2FmZS5uZXQgTHRkLg' +
  'EAAAAAAAAADAAAAAAAAABfcHVibGljTmFtZXMFAAAAAAAAAAAAAAABAAAAAgAAAAMAAAAEAAAA';

  const decodedReqForRandomClient = (uri) => helper.createRandomAccount()
    .then(() => client.decodeRequest(uri));

  describe('Unregistered client', () => {
    it.skip('gets back encoded response', () => (
      new Promise((resolve) => {
        client.decodeRequest(encodedUnRegisterAuthUri)
          .then((res) => {
            should(res).be.String();
            should(res.indexOf('safe-')).be.not.equal(-1);
            return resolve();
          });
      })
    ));
  });


  describe('after revoking', () => {
    before(() => new Promise(
      (resolve, reject) => {
        const authL = client.setListener(CONST.LISTENER_TYPES.AUTH_REQ, (err, req) => {
          const appId = req.authReq.app.id;
          return client.encodeAuthResp(req, true)
            .then(() => client.revokeApp(appId).then(() => {
              client.removeListener(CONST.LISTENER_TYPES.AUTH_REQ, authL);
              resolve();
            }));
        });

        const errL = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, (err) => {
          client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errL);
          reject(err);
        });

        decodedReqForRandomClient(encodedAuthUri);
      })
    );

    after(() => helper.clearAccount());

    it('same app can be registered again', () => (
      new Promise((resolve, reject) => {
        setTimeout(() => {
          const authL = client.setListener(CONST.LISTENER_TYPES.AUTH_REQ, (err, req) => (
            client.encodeAuthResp(req, true)
              .then(() => client.getRegisteredApps()
                .then((apps) => {
                  should(apps.length).be.equal(1);
                  client.removeListener(CONST.LISTENER_TYPES.AUTH_REQ, authL);
                  return resolve();
                }))
          ));
          const errL = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, (err) => {
            client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errL);
            reject(err);
          });
          client.decodeRequest(encodedAuthUri);
        }, 1000);
      }))
    );
  });

  describe('re-authorising', () => {
    before(() => new Promise(
      (resolve, reject) => {
        const authL = client.setListener(CONST.LISTENER_TYPES.AUTH_REQ,
          (err, req) => client.encodeAuthResp(req, true).then(() => {
            client.removeListener(CONST.LISTENER_TYPES.AUTH_REQ, authL);
            resolve();
          }));

        const errL = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, (err) => {
          client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errL);
          reject(err);
        });

        decodedReqForRandomClient(encodedAuthUri);
      })
    );

    after(() => helper.clearAccount());

    it.skip('doesn\'t throw error', () => (
      new Promise((resolve, reject) => {
        client.setListener(CONST.LISTENER_TYPES.AUTH_REQ, (err, req) => (
          client.encodeAuthResp(req, true)
            .then((res) => {
              should(res).not.be.empty().and.be.String();
              return resolve();
            })
        ));
        client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, reject);
        client.decodeRequest(encodedAuthUri);
      })
    ));
  });

  describe('account information', () => {
    before(() => new Promise(
      (resolve, reject) => {
        console.log('AND HERE WE ARE BEFORE PROMISE');
        const authL = client.setListener(CONST.LISTENER_TYPES.AUTH_REQ, (err, req) => (
          client.encodeAuthResp(req, true).then(() => {
            client.removeListener(CONST.LISTENER_TYPES.AUTH_REQ, authL);

            console.log('AND HERE WE ARE LISTENING AND RESOLVING');
            resolve();
          })
        ));

        const errL = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, () => {
          client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errL);
          console.log('AND HERE WE ARE LISTENING AND REJECTING');
          reject();
        });

        decodedReqForRandomClient(encodedAuthUri);
      })
    );

    after(() => helper.clearAccount());

    it('are retrievable', () => client.getAccountInfo()
      .should.be.fulfilled()
      .then((res) => {
        should(res).be.Object().and.not.empty().and.have.properties([
          'done',
          'available']);
        should(res.done).not.be.undefined().and.be.Number();
        should(res.available).not.be.undefined().and.be.Number();
        console.log('ACTUALLY TEST DONE (inside after promise)');
      })
    );

    console.log('ACTUALLY TEST DONE');
  });
});
