<?php

namespace SilverStripe\WebAuthn\Tests;

use InvalidArgumentException;
use Member;
use MFARegisteredMethod as RegisteredMethod;
use SapphireTest;
use SilverStripe\WebAuthn\CredentialRepository;
use Webauthn\AttestedCredentialData;

class CredentialRepositoryTest extends SapphireTest
{
    protected $usesDatabase = true;

    /**
     * @var Member
     */
    protected $member;

    /**
     * @var RegisteredMethod
     */
    protected $registeredMethod;

    /**
     * @var CredentialRepository
     */
    protected $repository;

    public function setUp()
    {
        parent::setUp();

        $this->member = new Member();
        $this->registeredMethod = new RegisteredMethod();
        $this->repository = new CredentialRepository($this->member, $this->registeredMethod);
    }

    public function testHas()
    {
        $this->registeredMethod->Data = json_encode([
            'data' => ['credentialId' => base64_encode('foobar')],
        ]);

        $this->assertTrue($this->repository->has('foobar'));
        $this->assertFalse($this->repository->has('barbaz'));
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Given credential ID does not match any database record
     */
    public function testGetThrowsExceptionOnInvalidCredentialId()
    {
        $this->repository->get('non-existent');
    }

    public function testGetReturnsAttestedCredentialData()
    {
        $this->registeredMethod->Data = json_encode([
            'data' => [
                'credentialId' => base64_encode('foobar'),
                'aaguid' => base64_encode('1234-5678-9012-3456'),
            ],
        ]);

        $this->assertInstanceOf(AttestedCredentialData::class, $this->repository->get('foobar'));
    }

    public function testGetUserHandleFor()
    {
        $this->registeredMethod->Data = json_encode([
            'data' => ['credentialId' => base64_encode('foobar')],
        ]);
        $this->member->ID = 123;

        $this->assertSame('123', $this->repository->getUserHandleFor('foobar'));
    }

    public function testGetCounterFor()
    {
        $this->registeredMethod->Data = json_encode([
            'data' => ['credentialId' => base64_encode('foobar')],
            'counter' => 5,
        ]);

        $this->assertSame(5, $this->repository->getCounterFor('foobar'));
    }

    public function testUpdateCounterFor()
    {
        $this->registeredMethod->Data = json_encode([
            'data' => ['credentialId' => base64_encode('foobar')],
            'counter' => 5,
        ]);

        $this->repository->updateCounterFor('foobar', 10);
        $this->assertSame(10, $this->repository->getCounterFor('foobar'));
    }
}
