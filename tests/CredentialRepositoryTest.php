<?php

namespace SilverStripe\WebAuthn\Tests;

use InvalidArgumentException;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\WebAuthn\CredentialRepository;
use Webauthn\AttestedCredentialData;

class CredentialRepositoryTest extends SapphireTest
{
    public function testHas()
    {
        $repo = CredentialRepository::fromArray($this->createTestCredentials(['foobar']), '1');

        $this->assertTrue($repo->has('foobar'));
        $this->assertFalse($repo->has('barbaz'));
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Given credential ID does not match any stored credentials
     */
    public function testGetThrowsExceptionOnInvalidCredentialId()
    {
        $repo = new CredentialRepository('1');
        $repo->get('non-existent');
    }

    public function testGetReturnsAttestedCredentialData()
    {
        $repo = CredentialRepository::fromArray($this->createTestCredentials(['foobar']), '1');

        $this->assertInstanceOf(AttestedCredentialData::class, $repo->get('foobar'));
    }

    public function testGetUserHandleFor()
    {
        $repo = CredentialRepository::fromArray($this->createTestCredentials(['foobar']), '123');

        $this->assertSame('123', $repo->getUserHandleFor('foobar'));
    }

    public function testGetCounterFor()
    {
        $repo = CredentialRepository::fromArray($this->createTestCredentials(['foobar'], 5), '1');

        $this->assertSame(5, $repo->getCounterFor('foobar'));
    }

    public function testUpdateCounterFor()
    {
        $repo = CredentialRepository::fromArray($this->createTestCredentials(['foobar']), '1');

        $repo->updateCounterFor('foobar', 10);
        $this->assertSame(10, $repo->getCounterFor('foobar'));
    }

    protected function createTestCredentials(array $names, $counterValue = 1)
    {
        $creds = [];

        foreach ($names as $id) {
            $creds[base64_encode($id)] = [
                'source' => [
                    'publicKeyCredentialId' => $id,
                    'type' => 'public-key',
                    'transports' =>
                        array (
                        ),
                    'attestationType' => 'none',
                    'trustPath' =>
                        array (
                            'type' => 'empty',
                        ),
                    'aaguid' => 'AAAAAAAAAAAAAAAAAAAAAA',
                    'credentialPublicKey' => 'pQECAyYgASFYII3gDdvOBje5JfjNO0VhxE2RrV5XoKqWmCZAmR0f9nFaIlggZOUvkovGH9cfeyfXEpJAVOzR1d-rVRZJvwWJf444aLo',
                    'userHandle' => 'MQ',
                    'counter' => 268,
                ],
                'counter' => $counterValue,
            ];
        }

        return $creds;
    }
}
