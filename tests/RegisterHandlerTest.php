<?php

namespace SilverStripe\WebAuthn\Tests;

use Exception;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\SessionStore;
use SilverStripe\Security\Member;
use SilverStripe\WebAuthn\CredentialRepository;
use SilverStripe\WebAuthn\RegisterHandler;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestedCredentialData;
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
use Webauthn\TrustPath\EmptyTrustPath;

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

    protected function setUp(): void
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

    protected function tearDown(): void
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
        $this->assertStringContainsString('Incomplete data', $result->getMessage());
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
        /** @var RegisterHandler&MockObject $handlerMock */
        $handlerMock = $this->getMockBuilder(RegisterHandler::class)
            ->setMethods(['getPublicKeyCredentialLoader', 'getAuthenticatorAttestationResponseValidator'])
            ->getMock();

        $publicKeyCredentialSourceMock = $this->createMock(PublicKeyCredentialSource::class);
        $responseValidatorMock = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $responseValidatorMock->method('check')->willReturn($publicKeyCredentialSourceMock);

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
            $this->assertStringContainsString($expectedResult->getMessage(), $result->getMessage());
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
            'publicKeyCredentialId' => 'cHVibGljS2V5Q3JlZGVudGlhbElk',
            'type' => 'public-key',
            'transports' =>
                array (
                ),
            'attestationType' => 'none',
            'trustPath' =>
                array (
                    'type' => EmptyTrustPath::class,
                ),
            'aaguid' => 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
            'credentialPublicKey' => 'cHVibGljS2V5',
            'userHandle' => 'dXNlckhhbmRsZQ',
            'counter' => 123456789,
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
                function (MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock
                        ->expects($this->once())
                        ->method('check')
                        ->willReturnCallback(function (): bool {
                            return true;
                        });
                },
            ],
            'valid response with existing credential' => [
                $responseMock,
                new Result(true),
                1,
                function (MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock
                        ->expects($this->once())
                        ->method('check')
                        ->willReturnCallback(function (): bool {
                            return true;
                        });
                },
                function (SessionStore $store) use ($testSource) {
                    $repo = new CredentialRepository((string) $store->getMember()->ID);
                    // phpcs:disable
                    $repo->saveCredentialSource(PublicKeyCredentialSource::createFromArray([
                        'publicKeyCredentialId' => 'cHVibGljS2V5Q3JlZGVudGlhbElk',
                        'type' => 'public-key',
                        'transports' =>
                            array (
                            ),
                        'attestationType' => 'none',
                        'trustPath' =>
                            array (
                                'type' => EmptyTrustPath::class,
                            ),
                        'aaguid' => 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
                        'credentialPublicKey' => 'cHVibGljS2V5',
                        'userHandle' => 'dXNlckhhbmRsZQ',
                        'counter' => 123456789,
                    ]));
                    // phpcs:enable
                    $store->addState(['repository' => $repo]);
                },
            ],
            'invalid response' => [
                $responseMock,
                new Result(false, 'I am a test'),
                0,
                function (MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($this->once())->method('check')
                        ->willThrowException(new Exception('I am a test'));
                },
            ],
        ];
    }
}
