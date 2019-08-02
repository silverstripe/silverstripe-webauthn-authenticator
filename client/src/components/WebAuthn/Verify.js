/* global window */

import React, { Component } from 'react';
import PropTypes from 'prop-types';
import publicKeyType from 'types/publicKey';
import { performVerification } from 'lib/auth';

import CircleTick from 'components/Icons/CircleTick';
import CircleWarning from 'components/Icons/CircleWarning';
import LoadingIndicator from 'components/LoadingIndicator';
import ActivateToken from '../Icons/ActivateToken';

const fallbacks = require('../../../lang/src/en.json');

class Verify extends Component {
  constructor(props) {
    super(props);

    this.state = {
      failure: false,
      success: false,
    };

    this.startAuth = this.startAuth.bind(this);
    this.handleRetry = this.handleRetry.bind(this);
  }

  handleRetry(event) {
    event.preventDefault();
    this.setState({
      failure: false,
    });
  }

  /**
   * Begins the Webauthn authentication process - presents the browser prompt to the user
   * This happens by delegating to {@see performVerification} which returns a promise that will
   * be completed after the process is complete.
   */
  startAuth() {
    const { publicKey, onCompleteVerification } = this.props;

    performVerification(publicKey)
      .then(verificationData => {
        this.setState(
          { success: true },
          () => setTimeout(
            () => { onCompleteVerification(verificationData); },
            1000
          )
        );
      })
      .catch(() => this.setState({ failure: true }));
  }

  /**
   * Render instructions for registering with this method
   *
   * @return {HTMLElement}
   */
  renderDescription() {
    const { ss: { i18n } } = window;
    const { method: { supportLink } } = this.props;

    const registerKeyT = i18n._t(
      'MFAWebAuthnVerify.VERIFY',
      fallbacks['MFAWebAuthnVerify.VERIFY']
    );

    // As this part of the message requires formatting, we render it using dangerouslySetInnerHTML
    const instructions = i18n.inject(
      i18n._t('MFAWebAuthnVerify.INSTRUCTION', fallbacks['MFAWebAuthnVerify.INSTRUCTION']),
      { button: `<strong>${registerKeyT}</strong>` }
    );

    return (
      <div className="mfa-verification-container__description">
        <p>
          {i18n._t('MFAWebAuthnVerify.DESCRIPTION', fallbacks['MFAWebAuthnVerify.DESCRIPTION'])}

          {supportLink &&
            <a
              href={supportLink}
              target="_blank"
              rel="noopener noreferrer"
            >
              {i18n._t('MFAWebAuthnVerify.HELP', fallbacks['MFAWebAuthnVerify.HELP'])}
            </a>
          }
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
    const { errors } = this.props;
    const { failure, success } = this.state;

    if (errors.length) {
      return (
        <div className="mfa-verification-container__status status-message--error">
          <span className="status-message__icon"><CircleWarning size="32px" /></span>
          <span className="status-message__description">
            {errors.join(', ')}
          </span>
        </div>
      );
    }

    if (success) {
      return (
        <div className="mfa-verification-container__status status-message--success">
          <span className="status-message__icon"><CircleTick size="32px" /></span>
          <span className="status-message__description">
            {i18n._t('MFAWebAuthnVerify.SUCCESS', fallbacks['MFAWebAuthnVerify.SUCCESS'])}
          </span>
        </div>
      );
    }

    if (failure) {
        return (
          <div className="mfa-verification-container__status status-message--failure">
            <span className="status-message__icon"><CircleWarning size="32px" /></span>
            <span className="status-message__description">
              {i18n._t('MFAWebAuthnVerify.FAILURE', fallbacks['MFAWebAuthnVerify.FAILURE'])}
            </span>
          </div>
        );
    }

    return (
      <div className="mfa-verification-container__status status-message--loading">
        <LoadingIndicator size="3em" />
        <span className="status-message__description">
          {i18n._t('MFAWebAuthnVerify.WAITING', fallbacks['MFAWebAuthnVerify.WAITING'])}
        </span>
      </div>
    );
  }

  /**
   * Render the icon related to this method
   *
   * @returns {HTMLElement}
   */
  renderThumbnail() {
    return (
      <div className="mfa-verification-container__thumbnail">
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
    const { moreOptionsControl } = this.props;
    const { failure, success } = this.state;

    if (success) {
      return <div className="mfa-verification-container__actions mfa-action-list" />;
    }

    const retryName = i18n._t('MFAWebAuthnVerify.RETRY', fallbacks['MFAWebAuthnVerify.RETRY']);
    const retryButton = (
      <button
        key={retryName}
        className="btn mfa-action-list__item btn-primary"
        disabled={false}
        onClick={this.handleRetry}
        type="button"
      >
        {retryName}
      </button>
    );

    return (
      <div className="mfa-verification-container__actions mfa-action-list">
        {failure ? retryButton : null}
        {moreOptionsControl}
      </div>
    );
  }

  render() {
    const { failure, success } = this.state;

    if (!failure && !success) {
      this.startAuth();
    }

    return (
      <div className="mfa-verification-container mfa-verification-container--web-authn">
        {this.renderDescription()}
        {this.renderStatus()}
        {this.renderThumbnail()}
        {this.renderActions()}
      </div>
    );
  }
}

Verify.propTypes = {
  method: PropTypes.object.isRequired,
  publicKey: publicKeyType,
  onCompleteVerification: PropTypes.func.isRequired,
  moreOptionsControl: PropTypes.func,
  errors: PropTypes.arrayOf(PropTypes.string),
};

Verify.defaultProps = {
  errors: [],
};

export default Verify;
