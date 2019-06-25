<?php

namespace SilverStripe\WebAuthn\Tests;

use Exception;
use PHPUnit_Framework_MockObject_MockObject;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\SessionStore;
use SilverStripe\Security\Member;
use SilverStripe\WebAuthn\RegisterHandler;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorData;
use Webauthn\AuthenticatorResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;

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
     * @var HTTPRequest
     */
    protected $request;

    /**
     * @var SessionStore
     */
    protected $store;

    /**
     * @var array
     */
    protected $originalServer;

    protected function setUp()
    {
        parent::setUp();

        $this->request = new HTTPRequest('GET', '/');
        $this->handler = Injector::inst()->create(RegisterHandler::class);

        $memberID = $this->logInWithPermission();
        /** @var Member $member */
        $this->member = Member::get()->byID($memberID);

        $this->store = new SessionStore($this->member);

        $this->originalServer = $_SERVER;

        // Set default configuration settings
        RegisterHandler::config()->set(
            'authenticator_attachment',
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM
        );
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

        $result = $this->handler->start($this->store);
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

    public function testAuthenticatorSelectionCriteriaRequiresCrossPlatformAttachmentByDefault()
    {
        $result = $this->handler->start($this->store);
        $this->assertArrayHasKey('keyData', $result);

        /** @var PublicKeyCredentialCreationOptions $options */
        $options = $result['keyData'];
        $this->assertInstanceOf(PublicKeyCredentialCreationOptions::class, $options);

        $authenticatorSelection = $options->getAuthenticatorSelection();
        $this->assertSame(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            $authenticatorSelection->getAuthenticatorAttachment()
        );
    }

    public function testStart()
    {
        $result = $this->handler->start($this->store);
        $this->assertArrayHasKey('keyData', $result);

        /** @var PublicKeyCredentialCreationOptions $options */
        $options = $result['keyData'];
        $this->assertInstanceOf(PublicKeyCredentialCreationOptions::class, $options);
    }

    public function testRegisterReturnsErrorWhenRequiredInformationIsMissing()
    {
        $result = $this->handler->register($this->request, $this->store);

        $this->assertFalse($result->isSuccessful());
        $this->assertContains('Incomplete data', $result->getMessage());
    }

    /**
     * @param AuthenticatorResponse $mockResponse
     * @param Result $expectedResult
     * @param callable $responseValidatorMockCallback
     * @dataProvider registerProvider
     */
    public function testRegister($mockResponse, $expectedResult, callable $responseValidatorMockCallback = null)
    {
        /** @var RegisterHandler&PHPUnit_Framework_MockObject_MockObject $handlerMock */
        $handlerMock = $this->getMockBuilder(RegisterHandler::class)
            ->setMethods(['getPublicKeyCredentialLoader', 'getAuthenticatorAttestationResponseValidator'])
            ->getMock();

        $responseValidatorMock = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        // Allow the data provider to customise the validation check handling
        if ($responseValidatorMockCallback) {
            $responseValidatorMockCallback($responseValidatorMock);
        }
        $handlerMock->expects($this->any())->method('getAuthenticatorAttestationResponseValidator')
            ->willReturn($responseValidatorMock);

        $loggerMock = $this->createMock(LoggerInterface::class);
        $handlerMock->setLogger($loggerMock);

        $loaderMock = $this->createMock(PublicKeyCredentialLoader::class);
        $handlerMock->expects($this->once())->method('getPublicKeyCredentialLoader')->willReturn($loaderMock);

        $publicKeyCredentialMock = $this->createMock(PublicKeyCredential::class);
        $loaderMock->expects($this->once())->method('load')->with('example')->willReturn(
            $publicKeyCredentialMock
        );

        $publicKeyCredentialMock->expects($this->once())->method('getResponse')->willReturn($mockResponse);

        $this->request->setBody(json_encode([
            'credentials' => base64_encode('example'),
        ]));

        $result = $handlerMock->register($this->request, $this->store);

        $this->assertSame($expectedResult->isSuccessful(), $result->isSuccessful());
        if ($expectedResult->getMessage()) {
            $this->assertContains($expectedResult->getMessage(), $result->getMessage());
        }
    }

    /**
     * Some centralised or reusable logic for testRegister. Note that some of the mocks are only used in some of the
     * provided data scenarios, but any expected call numbers are based on all scenarios being run.
     *
     * @return array[]
     */
    public function registerProvider()
    {
        $authDataMock = $this->createMock(AuthenticatorData::class);
        $authDataMock->expects($this->exactly(3))->method('hasAttestedCredentialData')
            // The first call is the "response indicates incomplete data" test case, second is "valid response",
            // third is "invalid response"
            ->willReturnOnConsecutiveCalls(false, true, true);

        $attestationMock = $this->createMock(AttestationObject::class);
        $attestationMock->expects($this->any())->method('getAuthData')->willReturn($authDataMock);

        $responseMock = $this->createMock(AuthenticatorAttestationResponse::class);
        $responseMock->expects($this->any())->method('getAttestationObject')->willReturn($attestationMock);

        return [
            'wrong response return type' => [
                // Deliberately the wrong child implementation of \Webauthn\AuthenticatorResponse
                $this->createMock(AuthenticatorAssertionResponse::class),
                new Result(false, 'Unexpected response type found'),
            ],
            'response indicates incomplete data' => [
                $responseMock,
                new Result(false, 'Incomplete data, required information missing'),
            ],
            'valid response' => [
                $responseMock,
                new Result(true),
                function (PHPUnit_Framework_MockObject_MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($this->once())->method('check')->willReturn(true);
                },
            ],
            'invalid response' => [
                $responseMock,
                new Result(false, 'I am a test'),
                function (PHPUnit_Framework_MockObject_MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($this->once())->method('check')
                        ->willThrowException(new Exception('I am a test'));
                },
            ],
        ];
    }

    public function testGetName()
    {
        $this->assertSame('Security key', $this->handler->getName());
    }

    public function testGetDescription()
    {
        $this->assertContains('A small USB device', $this->handler->getDescription());
    }

    public function testGetSupportLink()
    {
        RegisterHandler::config()->set('user_help_link', 'http://google.com');
        $this->assertSame('http://google.com', $this->handler->getSupportLink());
    }

    public function testGetComponent()
    {
        $this->assertSame('WebAuthnRegister', $this->handler->getComponent());
    }
}
