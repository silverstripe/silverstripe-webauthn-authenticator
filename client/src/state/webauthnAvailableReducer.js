/* global window */
/**
 * Adds information about whether WebAuthn is supported by the current browser into the Redux
 * store, so the application can react accordingly.
 *
 * @param {object} state
 * @returns {object}
 */
export default function webauthnAvailableReducer(state = {}) {
  let isAvailable = true;
  let unavailableMessage = null;

  // Enforce HTTPS
  if (window.location.protocol !== 'https:') {
    isAvailable = false;
    unavailableMessage = window.ss.i18n._t(
      'WebAuthnReducer.NOT_ON_HTTPS',
      'This method can only be used over HTTPS.',
    );
  } else if (typeof window.AuthenticatorResponse === 'undefined') {
    // Check for the WebAuthn browser API
    // See https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API#Interfaces
    isAvailable = false;
    unavailableMessage = window.ss.i18n._t(
      'WebAuthnReducer.UNSUPPORTED_BROWSER',
      'Security keys are not supported by this browser',
    );
  }

  // Only provide a "mfaRegister" state override if unavailable
  const webAuthnAvailable = isAvailable ? {} : {
    isAvailable,
    unavailableMessage,
  };

  return {
    ...state,
    ...webAuthnAvailable,
  };
}
