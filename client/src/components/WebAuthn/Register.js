/* global window */

import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { base64ToByteArray, byteArrayToBase64 } from 'lib/convert';

import CircleTick from '../Icons/CircleTick';
import CircleWarning from '../Icons/CircleWarning';
import LoadingIndicator from '../LoadingIndicator';

const fallbacks = require('../../../lang/src/en.json');

const VIEWS = {
  LOADING: 'LOADING', // Preparing to render the form
  READY: 'READY', // Waiting for the user to start the process
  REGISTERING: 'REGISTERING', // Waiting for the security key / server
  FAILURE: 'FAILURE', // Timeout or other error from registration
  SUCCESS: 'SUCCESS', // Successful registration
};

/**
 * This component provides the user interface for registering backup codes with a user. This process
 * only involves showing the user the backup codes. User input is not required to set up the codes.
 */
class Register extends Component {
  constructor(props) {
    super(props);

    this.state = {
      view: props.keyData ? VIEWS.READY : VIEWS.LOADING,
      registrationData: null,
    };

    this.handleBack = this.handleBack.bind(this);
    this.handleNext = this.handleNext.bind(this);
    this.handleStartRegistration = this.handleStartRegistration.bind(this);
  }

  /**
   * keyData may not be passed through on initial render, and we can't start without it.
   *
   * @todo Re-evaluate whether this code is required.
   */
  componentWillReceiveProps() {
    const { keyData } = this.props;
    const { view } = this.state;

    if (view === VIEWS.LOADING && keyData) {
      this.setState({ view: VIEWS.READY });
    }
  }

  /**
   * Start the WebAuthn registration process
   *
   * @returns {Promise<any>} Resolves if registration succeeds, rejects if not
   */
  initAuth() {
    const { keyData } = this.props;

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

    return new Promise((resolve, reject) => {
      navigator.credentials.create({ publicKey: parsedKey })
        .then(response => {
          this.setState({
            registrationData: {
              credentials: btoa(JSON.stringify({
                id: response.id,
                type: response.type,
                rawId: byteArrayToBase64(response.rawId),
                response: {
                  clientDataJSON: byteArrayToBase64(response.response.clientDataJSON),
                  attestationObject: byteArrayToBase64(response.response.attestationObject),
                },
              })),
            },
          });

          resolve();
        }).catch(error => {
          reject(error.message);
      });
    });
  }

  /**
   * Send the user back to the "select method" UI
   */
  handleBack() {
    this.props.onBack();
  }

  /**
   * Submit the registration and take the user to the next screen when processing is complete
   */
  handleNext() {
    const { registrationData } = this.state;

    // Something went wrong here...
    if (registrationData === null) {
      this.setState({ view: VIEWS.FAILURE });
    }

    this.props.onCompleteRegistration(registrationData);
  }

  /**
   * Trigger the WebAuthn registration handler, which will present a prompt in some browsers.
   */
  handleStartRegistration() {
    this.setState({ view: VIEWS.REGISTERING });
    this.initAuth()
      .then(() => this.setState({ view: VIEWS.SUCCESS }))
      .catch(() => this.setState({ view: VIEWS.FAILURE }));
  }

  /**
   * Render instructions for registering with this method
   *
   * @return {HTMLElement}
   */
  renderDescription() {
    const { ss: { i18n } } = window;
    const { method } = this.props;

    const registerKeyT = i18n._t(
      'MFAWebAuthnRegister.REGISTER',
      fallbacks['MFAWebAuthnRegister.REGISTER']
    );

    // As this part of the message requires formatting, we render it using dangerouslySetInnerHTML
    const instructions = i18n.inject(
      i18n._t('MFAWebAuthnRegister.INSTRUCTION', fallbacks['MFAWebAuthnRegister.INSTRUCTION']),
      { button: `<strong>${registerKeyT}</strong>` }
    );

    return (
      <div className="mfa-registration-container__description">
        <p>
          {i18n._t('MFAWebAuthnRegister.DESCRIPTION', fallbacks['MFAWebAuthnRegister.DESCRIPTION'])}

          <a
            href={method.supportLink}
            target="_blank"
            rel="noopener noreferrer"
          >
            {i18n._t('MFAWebAuthnRegister.HELP', fallbacks['MFAWebAuthnRegister.HELP'])}
          </a>
        </p>

        {/* eslint-disable-next-line react/no-danger */}
        <p dangerouslySetInnerHTML={{ __html: instructions }} />
      </div>
    );
  }

  /**
   * Render the status of the registration, with relevant iconography
   *
   * @returns {HTMLElement}
   */
  renderStatus() {
    const { ss: { i18n } } = window;

    switch (this.state.view) {
      case VIEWS.READY:
        return (<div className="mfa-registration-container__status status-message--empty" />);
      case VIEWS.REGISTERING:
      case VIEWS.LOADING:
      default:
        return (
          <div className="mfa-registration-container__status status-message--loading">
            <LoadingIndicator size="3em" />
            <span className="status-message__description">
              {i18n._t('MFAWebAuthnRegister.WAITING', fallbacks['MFAWebAuthnRegister.WAITING'])}
            </span>
          </div>
        );
      case VIEWS.SUCCESS:
        return (
          <div className="mfa-registration-container__status status-message--success">
            <span className="status-message__icon"><CircleTick size="32px" /></span>
            <span className="status-message__description">
              {i18n._t('MFAWebAuthnRegister.SUCCESS', fallbacks['MFAWebAuthnRegister.SUCCESS'])}
            </span>
          </div>
        );
      case VIEWS.FAILURE:
        return (
          <div className="mfa-registration-container__status status-message--failure">
            <span className="status-message__icon"><CircleWarning size="32px" /></span>
            <span className="status-message__description">
              {i18n._t('MFAWebAuthnRegister.FAILURE', fallbacks['MFAWebAuthnRegister.FAILURE'])}
            </span>
          </div>
        );
    }
  }

  /**
   * Render the icon related to this method
   *
   * @returns {HTMLElement}
   */
  renderThumbnail() {
    const { method } = this.props;

    return (
      <div className="mfa-registration-container__thumbnail">
        <img
          src={method.thumbnail}
          alt={method.name}
        />
      </div>
    );
  }

  /**
   * Render available actions based on current state of registration flow
   *
   * @return {HTMLElement}
   */
  renderActions() {
    const { view } = this.state;
    let actions = [];

    switch (view) {
      case VIEWS.FAILURE:
        actions = [
          { action: this.handleStartRegistration, name: 'Retry' },
          { action: this.handleBack, name: 'Back' },
        ];
        break;
      case VIEWS.READY:
        actions = [
          { action: this.handleStartRegistration, name: 'Register key' },
          { action: this.handleBack, name: 'Back' },
        ];
        break;
      case VIEWS.REGISTERING:
        actions = [
          { action: this.handleStartRegistration, name: 'Registering', disabled: true },
          { action: this.handleBack, name: 'Back', disabled: true },
        ];
        break;
      case VIEWS.LOADING:
      default:
        actions = [
          { action: this.handleStartRegistration, name: 'Registering', disabled: true },
          { action: this.handleBack, name: 'Back', disabled: false },
        ];
        break;
      case VIEWS.SUCCESS:
        actions = [{ action: this.handleNext, name: 'Next' }];
        break;
    }

    return (
      <div className="mfa-registration-container__actions">
        {
          actions.map((action, i) => {
            const firstAction = i === 0;
            return (
              <button
                key={action.name}
                className={firstAction ? 'btn btn-primary' : 'btn btn-link'}
                disabled={action.disabled || false}
                onClick={action.action}
                type="button"
              >
                {action.name}
              </button>
            );
          })
        }
      </div>
    );
  }

  render() {
    return (
      <div className="mfa-registration-container mfa-registration-container--web-authn">
        {this.renderDescription()}
        {this.renderStatus()}
        {this.renderThumbnail()}
        {this.renderActions()}
      </div>
    );
  }
}


Register.propTypes = {
  keyData: PropTypes.object,
  method: PropTypes.object.isRequired,
  onBack: PropTypes.func.isRequired,
  onCompleteRegistration: PropTypes.func.isRequired,
  // uri: PropTypes.string.isRequired,
};

Register.displayName = 'WebAuthnRegister';

export { Register as Component };

export default Register;
