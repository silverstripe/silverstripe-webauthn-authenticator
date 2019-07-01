/* global window */

import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { performRegistration } from 'lib/auth';

import CircleTick from 'components/Icons/CircleTick';
import CircleWarning from 'components/Icons/CircleWarning';
import LoadingIndicator from 'components/LoadingIndicator';
import ActivateToken from '../Icons/ActivateToken';

const fallbacks = require('../../../lang/src/en.json');

export const VIEWS = {
  LOADING: 'LOADING', // Preparing to render the form
  READY: 'READY', // Waiting for the user to start the process
  ERROR: 'ERROR', // Something went wrong while loading or processing
  PROMPTING: 'PROMPTING', // Waiting for the security key / server
  FAILURE: 'FAILURE', // Timeout or other error from prompting
  SUCCESS: 'SUCCESS', // Successful prompting, ready to proceed
};

/**
 * This component provides the UI for registering a security key with a user. This process involves
 * triggering a WebAuthn registration request, and sending the registration back to SilverStripe.
 */
class Register extends Component {
  constructor(props) {
    super(props);

    let view = VIEWS.LOADING;
    if (props.keyData) {
      view = VIEWS.READY;
    } else if (props.errors.length) {
      view = VIEWS.ERROR;
    }

    this.state = {
      view,
      registrationData: null,
    };

    this.handleBack = this.handleBack.bind(this);
    this.handleNext = this.handleNext.bind(this);
    this.handleStartRegistration = this.handleStartRegistration.bind(this);
  }

  /**
   * Monitor for the introduction of keyData to transition into READY state if it isn't present
   * during initial render.
   */
  componentDidUpdate() {
    const { keyData } = this.props;
    const { view } = this.state;

    if (view === VIEWS.LOADING && keyData) {
      // eslint-disable-next-line react/no-did-update-set-state
      this.setState({ view: VIEWS.READY });
    }
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
      return;
    }

    this.props.onCompleteRegistration(registrationData);
  }

  /**
   * Trigger the WebAuthn registration handler, which will present a prompt in some browsers.
   */
  handleStartRegistration() {
    this.setState({ view: VIEWS.PROMPTING });

    performRegistration(this.props.keyData)
      .then(registrationData => this.setState({ view: VIEWS.SUCCESS, registrationData }))
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
    const { errors } = this.props;
    const { ss: { i18n } } = window;

    switch (this.state.view) {
      case VIEWS.READY:
        return (<div className="mfa-registration-container__status status-message--empty" />);
      case VIEWS.PROMPTING:
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
      case VIEWS.ERROR:
        return (
          <div className="mfa-registration-container__status status-message--error">
            <span className="status-message__icon"><CircleWarning size="32px" /></span>
            <span className="status-message__description">
              {errors.join(', ')}
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
    return (
      <div className="mfa-registration-container__thumbnail">
        <ActivateToken />
      </div>
    );
  }

  /**
   * Render available actions based on current state of registration flow
   *
   * @return {HTMLElement}
   */
  renderActions() {
    const { ss: { i18n } } = window;
    const { view } = this.state;
    let actions = [];

    switch (view) {
      case VIEWS.FAILURE:
        actions = [
          {
            action: this.handleStartRegistration,
            name: i18n._t('MFAWebAuthnRegister.RETRY', fallbacks['MFAWebAuthnRegister.RETRY'])
          },
          {
            action: this.handleBack,
            name: i18n._t('MFAWebAuthnRegister.BACK', fallbacks['MFAWebAuthnRegister.BACK'])
          },
        ];
        break;
      case VIEWS.ERROR:
        // Deliberately do not provide any actions for backend errors, a refresh is required
        actions = [];
        break;
      case VIEWS.READY:
        actions = [
          {
            action: this.handleStartRegistration,
            name: i18n._t('MFAWebAuthnRegister.REGISTER', fallbacks['MFAWebAuthnRegister.REGISTER'])
          },
          {
            action: this.handleBack,
            name: i18n._t('MFAWebAuthnRegister.BACK', fallbacks['MFAWebAuthnRegister.BACK'])
          },
        ];
        break;
      case VIEWS.PROMPTING:
        actions = [
          {
            action: this.handleStartRegistration,
            name: i18n._t(
              'MFAWebAuthnRegister.REGISTERING',
              fallbacks['MFAWebAuthnRegister.REGISTERING']
            ),
            disabled: true
          },
          {
            action: this.handleBack,
            name: i18n._t('MFAWebAuthnRegister.BACK', fallbacks['MFAWebAuthnRegister.BACK']),
            disabled: true
          },
        ];
        break;
      case VIEWS.LOADING:
      default:
        actions = [
          {
            action: this.handleStartRegistration,
            name: i18n._t(
              'MFAWebAuthnRegister.REGISTERING',
              fallbacks['MFAWebAuthnRegister.REGISTERING']
            ),
            disabled: true,
          },
          {
            action: this.handleBack,
            name: i18n._t('MFAWebAuthnRegister.BACK', fallbacks['MFAWebAuthnRegister.BACK']),
          },
        ];
        break;
      case VIEWS.SUCCESS:
        actions = [
          {
            action: this.handleNext,
            name: i18n._t(
              'MFAWebAuthnRegister.COMPLETEREGISTRATION',
              fallbacks['MFAWebAuthnRegister.COMPLETEREGISTRATION']
            ),
          }];
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
                className={firstAction ? 'btn btn-primary' : 'btn btn-secondary'}
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
  errors: PropTypes.arrayOf(PropTypes.string),
  onBack: PropTypes.func.isRequired,
  onCompleteRegistration: PropTypes.func.isRequired,
};

Register.defaultProps = {
  errors: [],
};

Register.displayName = 'WebAuthnRegister';

export { Register as Component };

export default Register;
