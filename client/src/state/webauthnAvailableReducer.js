/* global window */
/**
 * Adds information about whether WebAuthn is supported by the current browser into the Redux
 * store, so the application can react accordingly.
 *
 * @param {object} state
 * @returns {object}
 */
export default function webauthnAvailableReducer(state = {}) {
  // See https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#Interfaces
  const isAvailable = typeof window.AuthenticatorResponse !== 'undefined';

  // Only provide a "mfaRegister" state override if unavailable
  const webAuthnAvailable = isAvailable ? {} : {
    isAvailable,
    unavailableMessage: window.ss.i18n._t(
      'WebAuthnReducer.UNSUPPORTED_BROWSER',
      'Security keys are not supported by this browser'
    ),
  };

  return {
    ...state,
    ...webAuthnAvailable,
  };
}
