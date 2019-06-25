<?php

namespace SilverStripe\WebAuthn;

use RuntimeException;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredentialLoader;

/**
 * Represents an error found when the AuthenticatorResponse from a challenge is not of the expected type
 * e.g. for verification we expect {@see AuthenticatorAssertionResponse}
 * but could instead be returned a {@see AuthenticatorAttestationResponse}
 * It is an extreme edge case, but is technically possible
 * {@see PublicKeyCredentialLoader::createResponse}
 */
class ResponseTypeException extends RuntimeException
{
}
