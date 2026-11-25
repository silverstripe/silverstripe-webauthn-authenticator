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
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorData;
use Webauthn\AuthenticatorResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\TrustPath\EmptyTrustPath;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

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
     */
    #[DataProvider('hostProvider')]
    public function testRelyingPartyEntityDomainIncludesSilverStripeDomain(string $baseUrl, string $expected)
    {
        $_SERVER['HTTP_HOST'] = $baseUrl;

        $result = $this->handler->start($this->store);
        $this->assertArrayHasKey('keyData', $result);

        // webauthn-lib 5: start() returns the options in the JSON form the browser receives
        $options = $result['keyData'];
        $this->assertIsArray($options);
        $this->assertSame(
            $expected,
            $options['rp']['id'] ?? null,
            'Relying party entity should identify the current SilverStripe domain'
        );
    }

    /**
     * @return array
     */
    public static function hostProvider(): array
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

        // webauthn-lib 5: start() returns the options in the JSON form the browser receives
        $options = $result['keyData'];
        $this->assertIsArray($options);
        $this->assertSame(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            $options['authenticatorSelection']['authenticatorAttachment']
        );
    }

    public function testStart()
    {
        $result = $this->handler->start($this->store);
        $this->assertArrayHasKey('keyData', $result);

        // webauthn-lib 5: start() returns the options in the JSON form the browser receives
        $options = $result['keyData'];
        $this->assertIsArray($options);
        $this->assertArrayHasKey('challenge', $options);
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
     */
    #[DataProvider('registerProvider')]
    public function testRegister(
        $mockResponse,
        $expectedResult,
        $expectedCredentialCount,
        ?callable $responseValidatorMockCallback = null,
        ?callable $storeModifier = null
    ) {
        /** @var RegisterHandler&MockObject $handlerMock */
        $handlerMock = $this->getMockBuilder(RegisterHandler::class)
            ->onlyMethods(['getSerializer', 'getAuthenticatorAttestationResponseValidator'])
            ->getMock();

        // webauthn-lib 5: check() returns a CredentialRecord, which register() now uses (duplicate ID check)
        $responseValidatorMock = $this->createMock(AuthenticatorAttestationResponseValidator::class);
        $responseValidatorMock->method('check')->willReturn(static::createTestRecord('publicKeyCredentialId'));

        // Allow the data provider to customise the validation check handling
        if ($responseValidatorMockCallback) {
            $responseValidatorMockCallback($responseValidatorMock);
        }
        $handlerMock->expects($this->any())->method('getAuthenticatorAttestationResponseValidator')
            ->willReturn($responseValidatorMock);

        $loggerMock = $this->createMock(LoggerInterface::class);
        $handlerMock->setLogger($loggerMock);

        // webauthn-lib 5 reads the credential through a serializer (PublicKeyCredentialLoader is gone), and
        // PublicKeyCredential exposes its response as a property, so a real one carries the mock response
        $serializerMock = $this->createMock(SerializerInterface::class);
        $handlerMock->expects($this->once())->method('getSerializer')->willReturn($serializerMock);
        $serializerMock->expects($this->once())->method('deserialize')
            ->with('example', PublicKeyCredential::class, 'json')
            ->willReturn(PublicKeyCredential::create('public-key', 'publicKeyCredentialId', $mockResponse));

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
    public static function registerProvider()
    {
        // The test credential (formerly PublicKeyCredentialSource::createFromArray(), see createTestRecord())
        $testSource = static::createTestRecord('publicKeyCredentialId');

        $testCase = new RegisterHandlerTest('MyTestCase');
        $authDataMock = $testCase->createMock(AuthenticatorData::class);
        $authDataMock->expects($testCase->exactly(5))->method('hasAttestedCredentialData')
            // The first call is the "response indicates incomplete data" test case, second is "valid response",
            // third is "valid response with existing credential", fourth is "response for an already registered
            // credential", fifth is "invalid response"
            ->willReturnOnConsecutiveCalls(false, true, true, true, true);
        // webauthn-lib 5 has no getAttestedCredentialData()/getSignCount() on AuthenticatorData (they are properties
        // now), and register() does not read them, so they are not stubbed any more

        // webauthn-lib 5 reads attestationObject and authData as properties, which a mock cannot provide: real
        // objects carry the mocked AuthenticatorData instead
        $attestationMock = AttestationObject::create(
            '',
            $testCase->createMock(AttestationStatement::class),
            $authDataMock
        );
        $responseMock = AuthenticatorAttestationResponse::create(
            $testCase->createMock(CollectedClientData::class),
            $attestationMock
        );

        return [
            'wrong response return type' => [
                // Deliberately the wrong child implementation of \Webauthn\AuthenticatorResponse
                $testCase->createMock(AuthenticatorAssertionResponse::class),
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
                function (MockObject $responseValidatorMock) use ($testCase) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock
                        ->expects($testCase->once())
                        ->method('check')
                        ->willReturn(static::createTestRecord('publicKeyCredentialId'));
                },
            ],
            'valid response with existing credential' => [
                $responseMock,
                new Result(true),
                1,
                function (MockObject $responseValidatorMock) use ($testCase) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock
                        ->expects($testCase->once())
                        ->method('check')
                        ->willReturn(static::createTestRecord('publicKeyCredentialId'));
                },
                function (SessionStore $store) use ($testSource) {
                    $repo = new CredentialRepository((string) $store->getMember()->ID);
                    // The member's existing key: a different credential than the one being registered. webauthn-lib 4
                    // refused a credential ID already in the repository inside its validator (mocked here); with
                    // webauthn-lib 5 register() does that check itself (see the next case)
                    $repo->saveCredentialSource(static::createTestRecord('existingCredentialId'));
                    $store->addState(['repository' => $repo]);
                },
            ],
            'response for an already registered credential' => [
                $responseMock,
                new Result(false, 'The credential ID is already registered'),
                0,
                function (MockObject $responseValidatorMock) use ($testCase) {
                    $responseValidatorMock
                        ->expects($testCase->once())
                        ->method('check')
                        ->willReturn(static::createTestRecord('publicKeyCredentialId'));
                },
                function (SessionStore $store) {
                    $repo = new CredentialRepository((string) $store->getMember()->ID);
                    $repo->saveCredentialSource(static::createTestRecord('publicKeyCredentialId'));
                    $store->addState(['repository' => $repo]);
                },
            ],
            'invalid response' => [
                $responseMock,
                new Result(false, 'I am a test'),
                0,
                function (MockObject $responseValidatorMock) use ($testCase) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($testCase->once())->method('check')
                        ->willThrowException(new Exception('I am a test'));
                },
            ],
        ];
    }

    /**
     * The credential these tests used with webauthn-lib 4, built with PublicKeyCredentialSource::createFromArray()
     * (removed in webauthn-lib 5) from the base64 of these same values. PublicKeyCredentialSource is deprecated in
     * webauthn-lib 5.3, so this is a CredentialRecord.
     */
    protected static function createTestRecord(string $credentialId): CredentialRecord
    {
        return CredentialRecord::create(
            $credentialId,
            'public-key',
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'),
            'publicKey',
            'userHandle',
            123456789
        );
    }
}
