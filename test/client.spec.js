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

  describe('decrypt request', () => {
    before(() => helper.createRandomAccount());

    after(() => helper.clearAccount());

    it('throws an error when encoded URI is empty', () =>
      client.decodeRequest().should.be.rejected()
    );

    it('throws an error for container request of unknown app', () => (
      new Promise((resolve, reject) => {
        const contListener = client.setListener(CONST.LISTENER_TYPES.CONTAINER_REQ, (err, res) => {
          client.removeListener(CONST.LISTENER_TYPES.CONTAINER_REQ, contListener);
          reject(res);
        });

        const errListener = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, (err) => {
          should(err).not.be.empty().and.be.String();
          client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errListener);
          resolve(err);
        });
        client.decodeRequest(encodedContUri);
      })
    ));

    it('throws an error for invalid URI', () => (
      new Promise((resolve, reject) => {
        const authListener = client.setListener(CONST.LISTENER_TYPES.AUTH_REQ, (err, res) => {
          client.removeListener(CONST.LISTENER_TYPES.AUTH_REQ, authListener);
          reject(res);
        });

        const errListener = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, (err) => {
          client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errListener);
          resolve(err);
        });

        client.decodeRequest(`safe-auth:${crypto.randomBytes(32).toString('base64')}`);
      })
    ));

    it('returns a decoded request for encoded Auth request', () => (
      new Promise((resolve, reject) => {
        const authListener = client.setListener(CONST.LISTENER_TYPES.AUTH_REQ, (err, res) => {
          should(res).not.be.undefined().and.be.Object().and.not.empty().and.have.properties(['reqId', 'authReq']);
          should(res.reqId).not.be.undefined().and.be.Number();
          should(res.authReq).be.Object().and.not.empty().and.have.properties([
            'app',
            'app_container',
            'containers',
            'containers_len',
            'containers_cap']);
          should(res.authReq.app).be.Object().and.not.empty().and.have.properties([
            'id',
            'scope',
            'name',
            'vendor']);
          should(res.authReq.app.id).not.be.undefined().and.not.be.empty().and.be.String();
          should(res.authReq.app.name).not.be.undefined().and.not.be.empty().and.be.String();
          should(res.authReq.app.vendor).not.be.undefined().and.not.be.empty().and.be.String();
          should(res.authReq.app_container).not.be.undefined().and.be.Boolean();
          should(res.authReq.containers).not.be.undefined().and.be.Array();
          should(res.authReq.containers_len).not.be.undefined().and.be.Number();
          should(res.authReq.containers_cap).not.be.undefined().and.be.Number();

          if (res.authReq.containers_len > 0) {
            const container0 = res.authReq.containers[0];
            should(container0).be.Object().and.not.empty().and.have.properties([
              'cont_name',
              'access'
            ]);
            should(container0.cont_name).not.be.undefined().and.not.be.empty().and.be.String();
            should(container0.access).not.be.undefined().and.not.be.empty().and.be.Object();
          }
          client.removeListener(CONST.LISTENER_TYPES.AUTH_REQ, authListener);
          return resolve();
        });

        const errListener = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, (err) => {
          client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errListener);
          reject(err);
        });

        client.decodeRequest(encodedAuthUri);
      })
    ));

    it('returns a decoded request for encoded Auth request without safe-auth: scheme', () => (
      new Promise((resolve, reject) => {
        const authListener = client.setListener(CONST.LISTENER_TYPES.AUTH_REQ, (err, res) => {
          should(res).not.be.undefined().and.be.Object().and.not.empty().and.have.properties(['reqId', 'authReq']);
          client.removeListener(CONST.LISTENER_TYPES.AUTH_REQ, authListener);
          return resolve();
        });

        const errListener = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, (err) => {
          client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errListener);
          reject(err);
        });

        client.decodeRequest(encodedAuthUri.replace('safe-auth:', ''));
      })
    ));

    it('retuns a decoded request for encoded Container request', () => (
      new Promise((resolve, reject) => {
        const contListener = client.setListener(CONST.LISTENER_TYPES.CONTAINER_REQ, (err, res) => {
          should(res).not.be.undefined().and.be.Object().and.not.empty().and.have.properties(['reqId', 'contReq']);
          should(res.reqId).not.be.undefined().and.be.Number();
          should(res.contReq).be.Object().and.not.empty().and.have.properties([
            'app',
            'containers',
            'containers_len',
            'containers_cap']);
          should(res.contReq.app).be.Object().and.not.empty().and.have.properties([
            'id',
            'scope',
            'name',
            'vendor']);
          should(res.contReq.app.id).not.be.undefined().and.not.be.empty().and.be.String();
          // should(res.contReq.app.scope).not.be.undefined().and.be.String();
          should(res.contReq.app.name).not.be.undefined().and.not.be.empty().and.be.String();
          should(res.contReq.app.vendor).not.be.undefined().and.not.be.empty().and.be.String();
          should(res.contReq.containers).not.be.undefined().and.be.Array();
          should(res.contReq.containers_len).not.be.undefined().and.be.Number();
          should(res.contReq.containers_cap).not.be.undefined().and.be.Number();

          if (res.contReq.containers_len > 0) {
            const container0 = res.contReq.containers[0];
            should(container0).be.Object().and.not.empty().and.have.properties([
              'cont_name',
              'access'
            ]);
            should(container0.cont_name).not.be.undefined().and.not.be.empty().and.be.String();
            should(container0.access).not.be.undefined().and.not.be.empty().and.be.Object();
          }
          client.removeListener(CONST.LISTENER_TYPES.CONTAINER_REQ, contListener);
          return resolve();
        });

        const authL = client.setListener(CONST.LISTENER_TYPES.AUTH_REQ, (err, req) => {
          client.encodeAuthResp(req, true).then(() => client.decodeRequest(encodedContUri));
          client.removeListener(CONST.LISTENER_TYPES.AUTH_REQ, authL);
        });

        const errL = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, (err) => {
          client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errL);
          reject(err);
        });

        client.decodeRequest(encodedAuthUri);
      }))
    );

    it('returns a decoded request for encoded Container request without safe-auth: scheme', () => (
      new Promise((resolve, reject) => {
        const contL = client.setListener(CONST.LISTENER_TYPES.CONTAINER_REQ, (err, res) => {
          should(res).not.be.undefined().and.be.Object().and.not.empty().and.have.properties(['reqId', 'contReq']);
          client.removeListener(CONST.LISTENER_TYPES.CONTAINER_REQ, contL);
          return resolve();
        });

        const authL = client.setListener(CONST.LISTENER_TYPES.AUTH_REQ, (err, req) => {
          client.removeListener(CONST.LISTENER_TYPES.AUTH_REQ, authL);
          reject(req);
        });

        const errL = client.setListener(CONST.LISTENER_TYPES.REQUEST_ERR, (err) => {
          client.removeListener(CONST.LISTENER_TYPES.REQUEST_ERR, errL);
          reject(err);
        });

        client.decodeRequest(encodedContUri);
      })
    ));



    console.log('ACTUALLY TEST DONE');
  });
});
