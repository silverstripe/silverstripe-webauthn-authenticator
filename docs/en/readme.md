# Developer documentation

## What is Web Authentication (WebAuthn)?

We use the [web-auth/webauthn-framework PHP library](https://github.com/web-auth/webauthn-framework) to provide support
for the Web Authentication protocol:

> Webauthn defines an API enabling the creation and use of strong, attested, scoped, public key-based credentials by
> web applications, for the purpose of strongly authenticating users.

This module is a SilverStripe wrapper for implementing this library, and provides the frontend UI components to work
with [the silverstripe/mfa module](https://github.com/silverstripe/silverstripe-mfa).

For more information about WebAuthn, see [the Guide to Web Authentication](https://webauthn.guide/).

## Configuration

### "Find out more" links

You can configure (or remove) the "Find out more" links shown to users when the "Security key" authentication method
option is shown in multi-factor authentication registration or verification flows by adjusting the user help link
in configuration:

```yaml
SilverStripe\WebAuthn\RegisterHandler:
  user_help_link: 'http://intranet.mycompany.com/help/how-to-use-mfa'
```

### Authenticator Selection Criteria

The way the `Webauthn\AuthenticatorSelectionCriteria` instance is configured will define how appropriate authenticators
are selected to participate in the creation operation of WebAuthn attestations. It has three settings, which are
explained in [the MDN web docs for authenticatorSelection](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/authenticatorSelection#Syntax).

The SilverStripe WebAuthn module allows you to configure the `authenticatorAttachment` option, which is responsible
for determining whether single or cross-platform authenticators can be used in the registration operation. The default
is that devices must be cross-platform (e.g. security keys) while single-platform devices (e.g. touch ID on mobile
phones) are disabled. You can adjust this setting by configuring
`SilverStripe\WebAuthn\RegisterHandler.authenticator_attachment` to use one of these options:

* `AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE`: allows either
* `AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM`: single-platform only
* `AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM `: cross-platform only

For more information, see [Authenticator Selection Criteria](https://github.com/web-auth/webauthn-framework/blob/v1.2/doc/webauthn/PublicKeyCredentialCreation.md#authenticator-selection-criteria)
