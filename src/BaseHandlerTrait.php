<?php

declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

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
        return AttestationStatementSupportManager::create([
            new NoneAttestationStatementSupport(),
            new FidoU2FAttestationStatementSupport(),
        ]);
    }

    /**
     * webauthn-lib 5 reads the browser's credential JSON through a Symfony serializer; it replaces the
     * PublicKeyCredentialLoader and AttestationObjectLoader of webauthn-lib 4.
     *
     * @param AttestationStatementSupportManager $attestationStatementSupportManager
     * @return SerializerInterface
     */
    protected function getSerializer(
        AttestationStatementSupportManager $attestationStatementSupportManager
    ): SerializerInterface {
        return (new WebauthnSerializerFactory($attestationStatementSupportManager))->create();
    }

    /**
     * webauthn-lib 5 configures the registration and login checks through a ceremony step manager; it
     * replaces the validator constructor arguments of webauthn-lib 4 (token binding handler, extension
     * output checker, algorithm manager).
     *
     * @param AttestationStatementSupportManager $attestationStatementSupportManager
     * @return CeremonyStepManagerFactory
     */
    protected function getCeremonyStepManagerFactory(
        AttestationStatementSupportManager $attestationStatementSupportManager
    ): CeremonyStepManagerFactory {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAttestationStatementSupportManager($attestationStatementSupportManager);
        return $factory;
    }
}
