/* global window */

import React, { Component } from 'react';
import PropTypes from 'prop-types';
import publicKeyType from 'types/publicKey';
import { performVerification } from '../../lib/auth';

import CircleWarning from '../Icons/CircleWarning';
import LoadingIndicator from '../LoadingIndicator';

const fallbacks = require('../../../lang/src/en.json');

class Verify extends Component {
  constructor(props) {
    super(props);

    this.state = {
      failure: false,
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

  startAuth() {
    const { publicKey, onCompleteVerification } = this.props;

    performVerification(publicKey)
      .then(verificationData => {
        onCompleteVerification(verificationData);
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
    const { method } = this.props;

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

          <a
            href={method.supportLink}
            target="_blank"
            rel="noopener noreferrer"
          >
            {i18n._t('MFAWebAuthnVerify.HELP', fallbacks['MFAWebAuthnVerify.HELP'])}
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

    if (this.state.failure) {
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
    const { method } = this.props;

    return (
      <div className="mfa-verification-container__thumbnail">
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
    const { moreOptionsControl } = this.props;
    const { failure } = this.state;

    const retryName = i18n._t('MFAWebAuthnVerify.RETRY', fallbacks['MFAWebAuthnVerify.RETRY']);
    const retryButton = (
      <button
        key={retryName}
        className="btn btn-primary"
        disabled={false}
        onClick={this.handleRetry}
        type="button"
      >
        {retryName}
      </button>
    );

    return (
      <div className="mfa-registration-container__actions">
        {failure ? retryButton : null}
        {moreOptionsControl}
      </div>
    );
  }

  render() {
    if (!this.state.failure) {
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
  publicKey: publicKeyType,
  onCompleteVerification: PropTypes.func,
  moreOptionsControl: PropTypes.func,
};

export default Verify;
