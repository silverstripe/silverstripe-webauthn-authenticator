# SilverStripe WebAuthn Authenticator

[![CI](https://github.com/silverstripe/silverstripe-webauthn-authenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/silverstripe/silverstripe-webauthn-authenticator/actions/workflows/ci.yml)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/silverstripe/silverstripe-webauthn-authenticator/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/silverstripe/silverstripe-webauthn-authenticator/?branch=master)
[![codecov](https://codecov.io/gh/silverstripe/silverstripe-webauthn-authenticator/branch/master/graph/badge.svg)](https://codecov.io/gh/silverstripe/silverstripe-webauthn-authenticator)
[![SilverStripe supported module](https://img.shields.io/badge/silverstripe-supported-0071C4.svg)](https://www.silverstripe.org/software/addons/silverstripe-commercially-supported-module-list/)

The silverstripe/webauthn-authenticator module provides a [Web Authentication (WebAuthn)](https://webauthn.guide/)
authentication method for the [silverstripe/mfa module](https://github.com/silverstripe/silverstripe-mfa), which
allows you to use the Web Authentication browser API to provide a second factor for your multi-factor authentication
login system.

The WebAuthn protocol supersedes FIDO U2F, while it still supports U2F-only authentication devices. 

By default, we expect that this module would be used with multi-platform authenticators such as a
[Yubikey security key](https://www.yubico.com/). You may choose to configure the module to support single-platform
authenticators such as fingerprint scanners. More information on this can be found in the
[developer documentation](docs/en/readme.md).

## Requirements

* SilverStripe ^4.1
* silverstripe/mfa ^4.0
* PHP GMP extension
* [Yarn](https://yarnpkg.com/lang/en/), [NodeJS](https://nodejs.org/en/) (>=10) and [npm](https://npmjs.com) (for building
  frontend assets)

## Installation

Install with Composer: 

```
composer require silverstripe/webauthn-authenticator ^4.0
```

For SilverStripe 3.7 support please use `silverstripe/webauthn-authenticator ^3.0`.

The WebAuthn authenticator module automatically configures itself when installed.

## Documentation

For detailed developer and CMS user documentation, see [the documentation readme](docs/en/readme.md).

## License

See [License](LICENSE.md)

## Bugtracker

Bugs are tracked in the issues section of this repository. Before submitting an issue please read over 
existing issues to ensure yours is unique. 
 
If the issue does look like a new bug:
 
 - Create a new issue
 - Describe the steps required to reproduce your issue, and the expected outcome. Unit tests, screenshots 
 and screencasts can help here.
 - Describe your environment as detailed as possible: SilverStripe version, Browser, PHP version, 
 Operating System, any installed SilverStripe modules.
 
Please report security issues to the module maintainers directly. Please don't file security issues in the bugtracker.
 
## Development and contribution

If you would like to make contributions to the module please ensure you raise a pull request and discuss with the module maintainers.
