/* global window */

import { base64ToByteArray, byteArrayToBase64 } from './convert';

/**
 * Start the WebAuthn registration process
 *
 * @returns {Promise<any>} Resolves if registration succeeds, rejects if not
 */
export const performRegistration = (keyData) => new Promise((resolve, reject) => {
  if (keyData.user === undefined || keyData.challenge === undefined) {
    reject('keyData not provided');
  }

  const user = {
    ...keyData.user,
    id: base64ToByteArray(keyData.user.id),
  };

  const parsedKey = {
    ...keyData,
    user,
    challenge: base64ToByteArray(keyData.challenge),
  };

  const { navigator } = window;

  navigator.credentials.create({ publicKey: parsedKey })
    .then(response => {
      resolve({
        credentials: btoa(JSON.stringify({
          id: response.id,
          type: response.type,
          rawId: byteArrayToBase64(response.rawId),
          response: {
            clientDataJSON: byteArrayToBase64(response.response.clientDataJSON),
            attestationObject: byteArrayToBase64(response.response.attestationObject),
          },
        })),
      });
    }).catch(error => {
      reject(error.message);
    });
});
