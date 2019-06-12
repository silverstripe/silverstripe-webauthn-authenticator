<?php

namespace SilverStripe\WebAuthn\Tests;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\MFA\Store\SessionStore;
use SilverStripe\Security\Member;
use SilverStripe\WebAuthn\RegisterHandler;
use Webauthn\PublicKeyCredentialCreationOptions;

class RegisterHandlerTest extends SapphireTest
{
    protected $usesDatabase = true;

    /**
     * @var RegisterHandler
     */
    protected $handler;

    /**
     * @var Member
     */
    protected $member;

    /**
     * @var array
     */
    protected $originalServer;

    protected function setUp()
    {
        parent::setUp();

        $this->handler = new RegisterHandler();

        $memberID = $this->logInWithPermission();
        /** @var Member $member */
        $this->member = Member::get()->byID($memberID);

        $this->originalServer = $_SERVER;
    }

    protected function tearDown()
    {
        $_SERVER = $this->originalServer;

        parent::tearDown();
    }

    /**
     * @param string $baseUrl
     * @param string $expected
     * @dataProvider hostProvider
     */
    public function testRelyingPartyEntityDomainIncludesSilverStripeDomain(string $baseUrl, string $expected)
    {
        $_SERVER['HTTP_HOST'] = $baseUrl;

        $store = new SessionStore($this->member);
        $result = $this->handler->start($store);

        $this->assertArrayHasKey('keyData', $result);

        /** @var PublicKeyCredentialCreationOptions $options */
        $options = $result['keyData'];
        $this->assertInstanceOf(PublicKeyCredentialCreationOptions::class, $options);

        $relyingPartyEntity = $options->getRp();
        $this->assertSame(
            $expected,
            $relyingPartyEntity->getId(),
            'Relying party entity should identify the current SilverStripe domain'
        );
    }

    /**
     * @return array
     */
    public function hostProvider(): array
    {
        return [
            'domain only' => ['http://example.com', 'example.com'],
            'domain with port' => ['https://example.com:8080', 'example.com'],
            'subdomain' => ['https://www.example.com', 'www.example.com'],
            'subdomain with port' => ['http://my.example.com:8887', 'my.example.com'],
            'subfolder' => ['https://example.com/mysite', 'example.com'],
            'subfolder with port' => ['http://example.com:8080/mysite', 'example.com'],
            'subdomain with subfolder' => ['http://my.example.com/mysite', 'my.example.com'],
            'subdomain with port and subfolder' => ['https://my.example.com:8080/mysite', 'my.example.com'],
            'credentials with domain and trailing slash' => ['http://foo:bar@example.com/', 'example.com'],
        ];
    }
}
