<?php declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use SilverStripe\MFA\Service\RegisteredMethodManager;
use SilverStripe\MFA\Store\StoreInterface;
use SilverStripe\Security\Member;
use Webauthn\PublicKeyCredentialUserEntity;

trait CredentialRepositoryProviderTrait
{
    /**
     * @param StoreInterface $store
     * @return CredentialRepository
     */
    protected function getCredentialRepository(StoreInterface $store): CredentialRepository
    {
        $state = $store->getState();

        // Check state from the store (session)
        if (isset($state['repository']) && $state['repository'] instanceof CredentialRepository) {
            return $state['repository'];
        }

        // Check if the member has an existing webauthn registered method to add to
        $member = $store->getMember();
        $method = RegisteredMethodManager::singleton()->getFromMember(
            $member,
            new Method()
        );

        if ($method) {
            // Unserialize is used here but it the class implements `Serializable` to serialise as JSON.
            $credentialRepository = CredentialRepository::fromArray(
                json_decode($method->Data, true),
                (string) $store->getMember()->ID
            );
        } else {
            $credentialRepository = new CredentialRepository((string)$member->ID);
        }

        // Persist the credential repository in the store
        $store->addState(['repository' => $credentialRepository]);

        return $credentialRepository;
    }

    /**
     * @param Member $member
     * @return PublicKeyCredentialUserEntity
     */
    protected function getUserEntity(Member $member): PublicKeyCredentialUserEntity
    {
        return new PublicKeyCredentialUserEntity(
            $member->getName(),
            (string) $member->ID,
            $member->getName()
        );
    }
}
