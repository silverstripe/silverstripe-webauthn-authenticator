<?php

namespace SilverStripe\WebAuthn;

use RuntimeException;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;

/**
 * Exception to be thrown when a {@see AuthenticatorAttestationResponse} is expected to contain attested credential
 * data but does not. {@see AuthenticatorData::hasAttestedCredentialData}
 */
class ResponseDataException extends RuntimeException
{
}
