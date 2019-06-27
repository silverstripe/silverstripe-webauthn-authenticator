/* global jest, describe, it, expect, window */

import reducer from '../webauthnAvailableReducer';

window.ss = {
  i18n: { _t: (key, string) => string },
};

describe('webauthnAvailableReducer', () => {
  it('detects when the website is not on HTTPS', () => {
    delete window.location;
    window.location = { protocol: 'http:' };

    expect(reducer(undefined)).toEqual({
      isAvailable: false,
      unavailableMessage: 'This method can only be used over HTTPS.',
    });
  });

  it('detects when web authentication API is not available in the window', () => {
    delete window.location;
    window.location = { protocol: 'https:' };
    window.AuthenticatorResponse = undefined;

    expect(reducer(undefined)).toEqual({
      isAvailable: false,
      unavailableMessage: 'Security keys are not supported by this browser',
    });
  });

  it('detects when web authentication API is available in the window', () => {
    delete window.location;
    window.location = { protocol: 'https:' };
    window.AuthenticatorResponse = jest.fn();

    expect(reducer(undefined)).toEqual({});
  });
});
