/* global window */

import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { base64ToByteArray, byteArrayToBase64 } from 'lib/convert';

/**
 * This component provides the user interface for registering backup codes with a user. This process
 * only involves showing the user the backup codes. User input is not required to set up the codes.
 */
class Register extends Component {
  componentDidMount() {
    const { keyData } = this.props;

    if (keyData) {
      this.initAuth();
    }
  }

  componentDidUpdate(prevProps) {
    const { keyData } = this.props;

    if (keyData && !prevProps.keyData) {
      this.initAuth();
    }
  }

  initAuth() {
    const { keyData, handleCompleteRegistration } = this.props;

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
        handleCompleteRegistration({
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
        console.log('nay', error.message);
      });
  }

  /**
   * Render the description for registering in with this method
   *
   * @return {HTMLElement}
   */
  renderDescription() {
    const { ss: { i18n } } = window;
    const { method } = this.props;

    return (
      <p>
        {i18n._t(
          'MFAWebAuthnRegister.DESCRIPTION',
          'Yo your browser should prompt you here'
        )}

        <a
          href={method.supportLink}
          target="_blank"
          rel="noopener noreferrer"
        >
          {i18n._t('MFARegister.HELP', 'Find out more')}
        </a>
      </p>
    );
  }

  render() {
    return (
      <div className="mfa-register-web-authn__container">
        {this.renderDescription()}
      </div>
    );
  }
}


Register.propTypes = {
  keyData: PropTypes.object,
};

export default Register;
