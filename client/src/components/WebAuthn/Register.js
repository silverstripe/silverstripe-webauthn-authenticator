/* global window */

import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { performRegistration } from 'lib/auth';

import CircleTick from '../Icons/CircleTick';
import CircleWarning from '../Icons/CircleWarning';
import LoadingIndicator from '../LoadingIndicator';

const fallbacks = require('../../../lang/src/en.json');

const VIEWS = {
  LOADING: 'LOADING', // Preparing to render the form
  READY: 'READY', // Waiting for the user to start the process
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

    this.state = {
      view: props.keyData ? VIEWS.READY : VIEWS.LOADING,
      registrationData: null,
    };

    this.handleBack = this.handleBack.bind(this);
    this.handleNext = this.handleNext.bind(this);
    this.handleStartRegistration = this.handleStartRegistration.bind(this);
  }

/**
 * We rely on a prop called `keyData` being present, however it may not be set upon the first
 * render of the component. We can check and wait for it via state.
 *
 * React 16 deprecates `componentWillReceiveProps` replacing it with `getDerivedStateFromProps`
 * for setting state in a functional manner. We have chosen to use {@see componentDidUpdate} over
 * `componentWillReceiveProps` in this component in order to provide the same functionality across
 * different (supported) build versions.
 * By having one delegate to the other we still save in maintenance costs.
 *
 * @param {Object} newProps incoming props for this component
 * @param {Object} currentState current stated of this component
 */
  static getDerivedStateFromProps(newProps, currentState) {
    if (currentState.view === VIEWS.LOADING && newProps.keyData) {
      return { view: VIEWS.READY };
    }
    return null;
  }

  /**
   * React docs (as at React 16) imply that one should try to avoid setting state in this method...
   * however if one is to do this, then it must be wrapped in a conditional in order to avoid
   * an infinite loop. This method has been chosen insead of `componentWillReceieveProps` which
   * is arguably the correct way to approach this, but it is deprecated in React 16 - we need
   * this component to function in both React 16 and React 15 (used by the CMS still @ 4.4.1).
   *
   * Quote from https://reactjs.org/docs/react-component.html#componentdidupdate :
   *
   * > You **may call `setState()` immediately** in componentDidUpdate() but note that
   * > **it must be wrapped in a condition** like in the example above, or you’ll cause an
   * > infinite loop. It would also cause an extra re-rendering which, while not visible to the
   * > user, can affect the component performance. If you’re trying to “mirror” some state to a
   * > prop coming from above, consider using the prop directly instead.
   * > [Read more about why copying props into state causes bugs.][1]
   * >
   * > [1]: https://reactjs.org/blog/2018/06/07/you-probably-dont-need-derived-state.html
   */
  componentDidUpdate() {
    const stateChange = Register.getDerivedStateFromProps(this.props, this.state);
    if (stateChange) {
      /* eslint-disable-next-line react/no-did-update-set-state */
      this.setState(stateChange);
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
  onBack: PropTypes.func.isRequired,
  onCompleteRegistration: PropTypes.func.isRequired,
  // uri: PropTypes.string.isRequired,
};

Register.displayName = 'WebAuthnRegister';

export { Register as Component };

export default Register;
