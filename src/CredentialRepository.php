<?php

declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use InvalidArgumentException;
use Serializable;
use Webauthn\AttestedCredentialData;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Implements the required interface from the WebAuthn library - but it does not implement the repository pattern in the
 * usual way. This is expected to be stored on a DataObject for persistence. Use the
 * @see CredentialRepository::hasChanged() API for determining whether a DataObject this is stored upon should be
 * persisted.
 */
class CredentialRepository implements PublicKeyCredentialSourceRepository, Serializable
{
    /**
     * @var string
     */
    private $memberID;

    /**
     * @var array
     */
    private $credentials = [];

    /**
     * @var bool
     */
    private $hasChanged = false;

    /**
     * @param string $memberID
     */
    public function __construct(string $memberID)
    {
        $this->memberID = $memberID;
    }

    public function has(string $credentialId): bool
    {
        return $this->findOneByCredentialId($credentialId) !== null;
    }

    public function get(string $credentialId): AttestedCredentialData
    {
        $this->assertCredentialID($credentialId);

        return $this->findOneByCredentialId($credentialId)->getAttestedCredentialData();
    }

    public function getUserHandleFor(string $credentialId): string
    {
        $this->assertCredentialID($credentialId);

        return $this->memberID;
    }

    public function getCounterFor(string $credentialId): int
    {
        $this->assertCredentialID($credentialId);

        return (int) $this->credentials[$this->getCredentialIDRef($credentialId)]['counter'];
    }

    public function updateCounterFor(string $credentialId, int $newCounter): void
    {
        $this->assertCredentialID($credentialId);

        $this->credentials[$this->getCredentialIDRef($credentialId)]['counter'] = $newCounter;
        $this->hasChanged = true;
    }

    /**
     * Assert that the given credential ID matches a stored credential
     *
     * @param string $credentialId
     */
    protected function assertCredentialID(string $credentialId): void
    {
        if (!$this->has($credentialId)) {
            throw new InvalidArgumentException('Given credential ID does not match any stored credentials');
        }
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $ref = $this->getCredentialIDRef($publicKeyCredentialId);
        if (!isset($this->credentials[$ref])) {
            return null;
        }

        return $this->credentials[$ref]['source'];
    }

    /**
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        // Only return credentials if the user entity shares the same ID.
        if ($publicKeyCredentialUserEntity->getId() !== $this->memberID) {
            return [];
        }

        return array_map(function ($credentialComposite) {
            return $credentialComposite['source'];
        }, $this->credentials);
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $ref = $this->getCredentialIDRef($publicKeyCredentialSource->getPublicKeyCredentialId());

        if (!isset($this->credentials[$ref])) {
            $this->credentials[$ref] = [
                'counter' => 0,
            ];
        }

        $this->credentials[$ref]['source'] = $publicKeyCredentialSource;
        $this->hasChanged = true;
    }

    /**
     * Empty the store deleting all stored credentials
     */
    public function reset(): void
    {
        $this->credentials = [];
    }

    /**
     * Indicates the repository has changed and should be persisted (as this doesn't follow the actual repository
     * pattern and is expected to be stored on a dataobject for persistence)
     *
     * @return bool
     */
    public function hasChanged(): bool
    {
        return $this->hasChanged;
    }

    /**
     * Set the credentials in bulk (for internal use) ensuring that credential objects are initialised correctly
     *
     * @param array $credentials
     */
    protected function setCredentials(array $credentials): void
    {
        $this->credentials = array_map(function ($data) {
            $data['source'] = PublicKeyCredentialSource::createFromArray($data['source']);
            return $data;
        }, $credentials);
    }

    /**
     * Create a reference to be used as a key for the credentials in the array
     *
     * @param string $credentialID
     * @return string
     */
    protected function getCredentialIDRef(string $credentialID): string
    {
        return base64_encode($credentialID);
    }

    /**
     * Provide the credentials stored in this repository as an array
     *
     * @return array
     */
    public function toArray(): array
    {
        return $this->credentials;
    }

    /**
     * Create an instance of a repository from the given credentials
     *
     * @param array $credentials
     * @param string $memberID
     * @return CredentialRepository
     */
    public static function fromArray(array $credentials, string $memberID): self
    {
        $new = new static($memberID);
        $new->setCredentials($credentials);

        return $new;
    }

    public function serialize()
    {
        return json_encode(['credentials' => $this->toArray(), 'memberID' => $this->memberID]);
    }

    public function unserialize($serialized)
    {
        $raw = json_decode($serialized, true);

        $this->memberID = $raw['memberID'];
        $this->setCredentials($raw['credentials']);
    }
}
