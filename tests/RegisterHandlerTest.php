<?php

namespace SilverStripe\WebAuthn\Tests;

use Config;
use Exception;
use Injector;
use Member;
use PHPUnit_Framework_MockObject_MockObject;
use SapphireTest;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\SessionStore;
use SilverStripe\WebAuthn\CredentialRepository;
use SilverStripe\WebAuthn\RegisterHandler;
use SS_HTTPRequest;
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
use Webauthn\PublicKeyCredentialSource;

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
     * @var SS_HTTPRequest
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

    public function setUp()
    {
        parent::setUp();

        $this->request = new SS_HTTPRequest('GET', '/');
        $this->handler = Injector::inst()->create(RegisterHandler::class);

        $memberID = $this->logInWithPermission();
        /** @var Member $member */
        $this->member = Member::get()->byID($memberID);

        $this->store = new SessionStore($this->member);

        $this->originalServer = $_SERVER;

        // Set default configuration settings
        RegisterHandler::config()->authenticator_attachment =
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    }

    public function tearDown()
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
        $oldBaseURL = Config::inst()->get('Director', 'alternate_base_url');
        Config::inst()->update('Director', 'alternate_base_url', $baseUrl);

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

        Config::inst()->update('Director', 'alternate_base_url', $oldBaseURL);
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
     * @param int $expectedCredentialCount
     * @param callable $responseValidatorMockCallback
     * @throws Exception
     * @dataProvider registerProvider
     */
    public function testRegister(
        $mockResponse,
        $expectedResult,
        $expectedCredentialCount,
        callable $responseValidatorMockCallback = null,
        callable $storeModifier = null
    ) {
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

        $loaderMock = $this->createMock(PublicKeyCredentialLoader::class);
        $handlerMock->expects($this->once())->method('getPublicKeyCredentialLoader')->willReturn($loaderMock);

        $publicKeyCredentialMock = $this->createMock(PublicKeyCredential::class);
        $loaderMock->expects($this->once())->method('load')->with('example')->willReturn(
            $publicKeyCredentialMock
        );

        $publicKeyCredentialMock->expects($this->any())->method('getResponse')->willReturn($mockResponse);

        $this->request->setBody(json_encode([
            'credentials' => base64_encode('example'),
        ]));

        if ($storeModifier) {
            $storeModifier($this->store);
        }

        $result = $handlerMock->register($this->request, $this->store);

        $this->assertSame($expectedResult->isSuccessful(), $result->isSuccessful());
        if ($expectedResult->getMessage()) {
            $this->assertContains($expectedResult->getMessage(), $result->getMessage());
        }

        $this->assertCount(
            $expectedCredentialCount,
            $result->getContext(),
            'The number of credentials stored is expected'
        );
    }

    /**
     * Some centralised or reusable logic for testRegister. Note that some of the mocks are only used in some of the
     * provided data scenarios, but any expected call numbers are based on all scenarios being run.
     *
     * @return array[]
     */
    public function registerProvider()
    {
        // phpcs:disable
        $testSource = PublicKeyCredentialSource::createFromArray([
            'publicKeyCredentialId' => 'g8e1UH4B1gUYl_7AiDXHTp8SE3cxYnpC6jF3Fo0KMm79FNN_e34hDE1Mnd4FSOoNW6B-p7xB2tqj28svkJQh1Q',
            'type' => 'public-key',
            'transports' => [],
            'attestationType' => 'none',
            'trustPath' => [
                'type' => 'empty',
            ],
            'aaguid' => 'AAAAAAAAAAAAAAAAAAAAAA',
            'credentialPublicKey' => 'pQECAyYgASFYII3gDdvOBje5JfjNO0VhxE2RrV5XoKqWmCZAmR0f9nFaIlggZOUvkovGH9cfeyfXEpJAVOzR1d-rVRZJvwWJf444aLo',
            'userHandle' => 'MQ',
            'counter' => 268,
        ]);
        // phpcs:enable

        $authDataMock = $this->createMock(AuthenticatorData::class);
        $authDataMock->expects($this->exactly(4))->method('hasAttestedCredentialData')
            // The first call is the "response indicates incomplete data" test case, second is "valid response",
            // third is "invalid response"
            ->willReturnOnConsecutiveCalls(false, true, true, true);
        $authDataMock->expects($this->any())->method('getAttestedCredentialData')->willReturn(
            $testSource->getAttestedCredentialData()
        );
        $authDataMock->expects($this->any())->method('getSignCount')->willReturn(1);

        $attestationMock = $this->createMock(AttestationObject::class);
        $attestationMock->expects($this->any())->method('getAuthData')->willReturn($authDataMock);

        $responseMock = $this->createMock(AuthenticatorAttestationResponse::class);
        $responseMock->expects($this->any())->method('getAttestationObject')->willReturn($attestationMock);

        return [
            'wrong response return type' => [
                // Deliberately the wrong child implementation of \Webauthn\AuthenticatorResponse
                $this->createMock(AuthenticatorAssertionResponse::class),
                new Result(false, 'Unexpected response type found'),
                0,
            ],
            'response indicates incomplete data' => [
                $responseMock,
                new Result(false, 'Incomplete data, required information missing'),
                0,
            ],
            'valid response' => [
                $responseMock,
                new Result(true),
                1,
                function (PHPUnit_Framework_MockObject_MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($this->once())->method('check')->willReturn(true);
                },
            ],
            'valid response with existing credential' => [
                $responseMock,
                new Result(true),
                1,
                function (PHPUnit_Framework_MockObject_MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($this->once())->method('check')->willReturn(true);
                },
                function (SessionStore $store) use ($testSource) {
                    $repo = new CredentialRepository((string) $store->getMember()->ID);
                    // phpcs:disable
                    $repo->saveCredentialSource(PublicKeyCredentialSource::createFromArray([
                        'publicKeyCredentialId' => 'g8e1UH4B1gUYl_7AiDXHTp8SE3cxYnpC6jF3Fo0KMm79FNN_e34hDE1Mnd4FSOoNW245125129518925891',
                        'type' => 'public-key',
                        'transports' => [],
                        'attestationType' => 'none',
                        'trustPath' => [
                            'type' => 'empty',
                        ],
                        'aaguid' => 'AAAAAAAAAAAAAAAAAAAAAA',
                        'credentialPublicKey' => 'pQECAyYgASFYII3gDdvOBje5JfjNO0VhxE2RrV5XoKqWmCZAmR0f9nFaIlggZOUvkovGH9cfeyfXEpJAVOzR1d-rVRZJvwWJf444aLo',
                        'userHandle' => 'MQ',
                        'counter' => 268,
                    ]));
                    // phpcs:enable
                    $store->addState(['repository' => $repo]);
                },
            ],
            'invalid response' => [
                $responseMock,
                new Result(false, 'I am a test'),
                0,
                function (PHPUnit_Framework_MockObject_MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($this->once())->method('check')
                        ->willThrowException(new Exception('I am a test'));
                },
            ],
        ];
    }
}
