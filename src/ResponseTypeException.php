<?php

namespace SilverStripe\WebAuthn;

use RuntimeException;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Denormalizer\AuthenticatorResponseDenormalizer;

/**
 * Represents an error found when the AuthenticatorResponse from a challenge is not of the expected type
 * e.g. for verification we expect {@see AuthenticatorAssertionResponse}
 * but could instead be returned a {@see AuthenticatorAttestationResponse}
 * It is an extreme edge case, but is technically possible
 * {@see AuthenticatorResponseDenormalizer}
 * (webauthn-lib 5; PublicKeyCredentialLoader::createResponse in webauthn-lib 4)
 */
class ResponseTypeException extends RuntimeException
{
}
