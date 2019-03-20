<?php
namespace SilverStripe\WebAuthn;

use InvalidArgumentException;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\Security\Member;
use Webauthn\AttestedCredentialData;
use Webauthn\CredentialRepository as CredentialRepositoryInterface;

/**
 * This interface is required by the WebAuthn library but is too exhaustive for our "one security key per person"
 * registration. We only support one and it's stored on the registered method that's a dependency of the constructor
 */
class CredentialRepository implements CredentialRepositoryInterface
{
    /**
     * @var RegisteredMethod
     */
    protected $registeredMethod;

    /**
     * @var Member
     */
    protected $member;

    /**
     * CredentialRepository constructor.
     * @param Member $member
     * @param RegisteredMethod $registeredMethod
     */
    public function __construct(Member $member, RegisteredMethod $registeredMethod = null)
    {
        $this->member = $member;
        $this->registeredMethod = $registeredMethod;
    }

    public function has(string $credentialId): bool
    {
        $data = $this->getCredentialData()['data'] ?? [];

        return isset($data['credentialId']) && $data['credentialId'] === base64_encode($credentialId);
    }

    public function get(string $credentialId): AttestedCredentialData
    {
        $this->assertCredentialID($credentialId);

        $data = $this->getCredentialData();

        return AttestedCredentialData::createFromJson($data['data']);
    }

    public function getUserHandleFor(string $credentialId): string
    {
        $this->assertCredentialID($credentialId);

        return $this->member->ID;
    }

    public function getCounterFor(string $credentialId): int
    {
        $this->assertCredentialID($credentialId);

        return (int) $this->getCredentialData()['counter'];
    }

    public function updateCounterFor(string $credentialId, int $newCounter): void
    {
        $this->assertCredentialID($credentialId);

        $this->registeredMethod->Data = json_encode([
            'counter' => $newCounter,
        ] + $this->getCredentialData());
        $this->registeredMethod->write();
    }

    protected function getCredentialData()
    {
        if (!$this->registeredMethod) {
            return [];
        }

        return json_decode($this->registeredMethod->Data, true) ?: [];
    }

    /**
     * @param string $credentialId
     */
    protected function assertCredentialID(string $credentialId): void
    {
        if (!$this->has($credentialId)) {
            throw new InvalidArgumentException('Given credential ID does not match any database record');
        }
    }
}
