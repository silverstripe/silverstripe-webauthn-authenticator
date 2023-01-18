<?php

declare(strict_types=1);

namespace SilverStripe\WebAuthn;

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
     * @return AttestationStatementSupportManager
     */
    protected function getAttestationStatementSupportManager(): AttestationStatementSupportManager
    {
        $manager = new AttestationStatementSupportManager();
        $manager->add(new NoneAttestationStatementSupport());
        $manager->add(new FidoU2FAttestationStatementSupport());
        return $manager;
    }

    /**
     * @param AttestationStatementSupportManager $attestationStatementSupportManager
     * @return AttestationObjectLoader
     */
    protected function getAttestationObjectLoader(
        AttestationStatementSupportManager $attestationStatementSupportManager
    ): AttestationObjectLoader {
        return new AttestationObjectLoader($attestationStatementSupportManager);
    }

    /**
     * @param AttestationObjectLoader $attestationObjectLoader
     * @return PublicKeyCredentialLoader
     */
    protected function getPublicKeyCredentialLoader(
        AttestationObjectLoader $attestationObjectLoader
    ): PublicKeyCredentialLoader {
        return new PublicKeyCredentialLoader($attestationObjectLoader);
    }
}
