<?php declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use InvalidArgumentException;
use Serializable;
use Webauthn\AttestedCredentialData;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * This interface is required by the WebAuthn library but is too exhaustive for our "one security key per person"
 * registration. We only support one and it's stored on the RegisteredMethod that is a dependency of the constructor
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

        return array_map(function($credentialComposite) {
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

    public function hasChanged(): bool
    {
        return $this->hasChanged;
    }

    protected function setCredentials(array $credentials): void
    {
        $this->credentials = array_map(function ($data) {
            $data['source'] = PublicKeyCredentialSource::createFromArray($data['source']);
            return $data;
        }, $credentials);
    }

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
    public static function fromArray(array $credentials, string $memberID)
    {
        $new = new static($memberID);
        $new->setCredentials($credentials);

        return $new;
    }

    /**
     * String representation of object
     * @link https://php.net/manual/en/serializable.serialize.php
     * @return string the string representation of the object or null
     * @since 5.1.0
     */
    public function serialize()
    {
        return json_encode(['credentials' => $this->toArray(), 'memberID' => $this->memberID]);
    }

    /**
     * Constructs the object
     * @link https://php.net/manual/en/serializable.unserialize.php
     * @param string $serialized <p>
     * The string representation of the object.
     * </p>
     * @return void
     * @since 5.1.0
     */
    public function unserialize($serialized)
    {
        $raw = json_decode($serialized, true);

        $this->memberID = $raw['memberID'];
        $this->setCredentials($raw['credentials']);
    }
}
