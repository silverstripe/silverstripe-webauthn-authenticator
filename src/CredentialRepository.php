<?php

declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use InvalidArgumentException;
use Serializable;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestedCredentialData;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Holds the credentials of one member. webauthn-lib 5 no longer has a repository interface (webauthn-lib 4 had
 * PublicKeyCredentialSourceRepository, which this class implemented); the method names are kept. It does not
 * implement the repository pattern in the usual way. This is expected to be stored on a DataObject for persistence.
 * Use the
 * @see CredentialRepository::hasChanged() API for determining whether a DataObject this is stored upon should be
 * persisted.
 */
class CredentialRepository
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

    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        $ref = $this->getCredentialIDRef($publicKeyCredentialId);
        if (!isset($this->credentials[$ref])) {
            return null;
        }

        return $this->credentials[$ref]['source'];
    }

    /**
     * @return CredentialRecord[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        // Only return credentials if the user entity shares the same ID.
        if ($publicKeyCredentialUserEntity->id !== $this->memberID) {
            return [];
        }

        return array_map(function ($credentialComposite) {
            return $credentialComposite['source'];
        }, $this->credentials ?? []);
    }

    public function saveCredentialSource(CredentialRecord $publicKeyCredentialSource): void
    {
        $ref = $this->getCredentialIDRef($publicKeyCredentialSource->publicKeyCredentialId);

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
            if (is_array($data['source'])) {
                # Stored data (RegisteredMethod.Data) keeps the webauthn-lib 4 JSON shape; webauthn-lib 5 reads it
                # through its CredentialRecordDenormalizer (see toArray())
                $data['source'] = static::getSerializer()->denormalize($data['source'], CredentialRecord::class);
            }
            return $data;
        }, $credentials ?? []);
    }

    /**
     * Create a reference to be used as a key for the credentials in the array
     *
     * @param string $credentialID
     * @return string
     */
    protected function getCredentialIDRef(string $credentialID): string
    {
        return base64_encode($credentialID ?? '');
    }

    /**
     * Provide the credentials stored in this repository as an array
     *
     * @return array
     */
    public function toArray(): array
    {
        # webauthn-lib 4 objects serialised themselves to JSON (JsonSerializable); webauthn-lib 5 objects do not, so
        # a plain json_encode() of them (silverstripe/mfa stores the register result that way) would lose the
        # credential. Normalise each source to an array instead.
        return array_map(function ($data) {
            if ($data['source'] instanceof CredentialRecord) {
                $data['source'] = static::normaliseSource($data['source']);
            }
            return $data;
        }, $this->credentials ?? []);
    }

    /**
     * The webauthn-lib 5 normalised form of a credential, in the JSON shape webauthn-lib 4 wrote.
     *
     * webauthn-lib 5 writes the trust path without its "type" key. webauthn-lib 4.4 to 4.8 need that key to read it
     * back (TrustPathLoader: "The trust path type is missing"); 4.9 reads both forms. 4.4.3 is what projects fall
     * back to when Composer blocks 4.9.x for its advisories. The key is added again, so data written after an upgrade
     * still loads if a site has to roll back. webauthn-lib 5 reads both forms (TrustPathDenormalizer).
     *
     * @param CredentialRecord $source
     * @return array
     */
    protected static function normaliseSource(CredentialRecord $source): array
    {
        $normalised = static::getSerializer()->normalize($source);
        if ($source->trustPath instanceof CertificateTrustPath) {
            $normalised['trustPath'] = ['type' => CertificateTrustPath::class] + $normalised['trustPath'];
        } elseif ($source->trustPath instanceof EmptyTrustPath) {
            $normalised['trustPath'] = ['type' => EmptyTrustPath::class];
        }
        return $normalised;
    }

    /**
     * Reads and writes stored credentials. No attestation formats are involved here, so the default support manager
     * is enough.
     *
     * @return NormalizerInterface&DenormalizerInterface
     */
    protected static function getSerializer()
    {
        return (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();
    }

    /**
     * Create an instance of a repository from the given credentials
     *
     * @param array $credentials
     * @param string $memberID
     * @return CredentialRepository
     */
    public static function fromArray(array $credentials, string $memberID): CredentialRepository
    {
        $new = new static($memberID);
        $new->setCredentials($credentials);

        return $new;
    }

    public function __serialize(): array
    {
        return [
            'memberID' => $this->memberID,
            'credentials' => $this->toArray()
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->memberID = $data['memberID'];
        $this->setCredentials($data['credentials']);
    }
}
