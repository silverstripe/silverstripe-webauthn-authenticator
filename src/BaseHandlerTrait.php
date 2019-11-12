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

/**
 * Contains logic which is shared between both WebAuthn's RegisterHandler and VerifyHandler, such as
 * the attestation configuration options.
 */
trait BaseHandlerTrait
{
    /**
     * @return Decoder
     */
    protected function getDecoder(): Decoder
    {
        return new Decoder(new TagObjectManager(), new OtherObjectManager());
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
        return new AttestationObjectLoader($attestationStatementSupportManager, $decoder);
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
        return new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);
    }
}
