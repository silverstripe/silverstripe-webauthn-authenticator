<?php

declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\PublicKeyCredentialLoader;
use SilverStripe\Dev\Deprecation;

/**
 * Contains logic which is shared between both WebAuthn's RegisterHandler and VerifyHandler, such as
 * the attestation configuration options.
 */
trait BaseHandlerTrait
{
    /**
     * @return Decoder
     *
     * @deprecated 4.5.0 Will be removed without equivalent functionality to replace it
     *
     * No longer needed as of v3 of webauthn-lib the Decoder is now created within both:
     * AttestationObjectLoader::__construct()
     * AuthenticatorAssertionResponseValidator::__construct()
     */
    protected function getDecoder(): Decoder
    {
        return Deprecation::withNoReplacement(function () {
            Deprecation::notice('4.5.0', 'Will be removed without equivalent functionality to replace it');
            return new Decoder(new TagObjectManager(), new OtherObjectManager());
        });
    }

    /**
     * @param Decoder $decoder
     * @return AttestationStatementSupportManager
     */
    protected function getAttestationStatementSupportManager(Decoder $decoder): AttestationStatementSupportManager
    {
        $manager = new AttestationStatementSupportManager();
        $manager->add(new NoneAttestationStatementSupport());
        $manager->add(new FidoU2FAttestationStatementSupport($decoder));
        return $manager;
    }

    /**
     * @param AttestationStatementSupportManager $attestationStatementSupportManager
     * @param Decoder $decoder
     * @return AttestationObjectLoader
     */
    protected function getAttestationObjectLoader(
        AttestationStatementSupportManager $attestationStatementSupportManager,
        Decoder $decoder
    ): AttestationObjectLoader {
        return new AttestationObjectLoader($attestationStatementSupportManager);
    }

    /**
     * @param AttestationObjectLoader $attestationObjectLoader
     * @param Decoder $decoder
     * @return PublicKeyCredentialLoader
     */
    protected function getPublicKeyCredentialLoader(
        AttestationObjectLoader $attestationObjectLoader,
        Decoder $decoder
    ): PublicKeyCredentialLoader {
        return new PublicKeyCredentialLoader($attestationObjectLoader);
    }
}
