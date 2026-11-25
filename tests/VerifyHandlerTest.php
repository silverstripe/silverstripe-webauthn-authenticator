<?php

namespace SilverStripe\WebAuthn\Tests;

use Exception;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\SessionStore;
use SilverStripe\Security\Member;
use SilverStripe\WebAuthn\VerifyHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorResponse;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\TrustPath\EmptyTrustPath;
use SilverStripe\WebAuthn\ResponseDataException;
use PHPUnit\Framework\Attributes\DataProvider;

class VerifyHandlerTest extends SapphireTest
{
    protected $usesDatabase = true;

    /**
     * @var VerifyHandler
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
     * @var RegisteredMethod
     */
    protected $registeredMethod;

    /**
     * @var array
     */
    protected $mockData = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->request = new HTTPRequest('GET', '/');
        $this->handler = Injector::inst()->create(VerifyHandler::class);

        $memberID = $this->logInWithPermission();
        /** @var Member $member */
        $this->member = Member::get()->byID($memberID);

        $this->store = new SessionStore($this->member);

        $this->registeredMethod = new RegisteredMethod();

        // phpcs:disable
        $this->registeredMethod->Data = json_encode([
            'cHVibGljS2V5Q3JlZGVudGlhbElk' => [
                'source' => [
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
                ],
                'counter' => 0,
            ]
        ]);
        // phpcs:enable
    }

    public function testStartThrowsExceptionWithMissingData()
    {
        $this->expectException(\SilverStripe\MFA\Exception\AuthenticationFailedException::class);
        $this->registeredMethod->Data = '';
        $this->handler->start($this->store, $this->registeredMethod);
    }

    public function testStart()
    {
        $result = $this->handler->start($this->store, $this->registeredMethod);
        $this->assertArrayHasKey('publicKey', $result);
    }

    public function testVerifyReturnsErrorWhenRequiredInformationIsMissing()
    {
        $this->registeredMethod->Data = null;
        $result = $this->handler->verify($this->request, $this->store, $this->registeredMethod);

        $this->assertFalse($result->isSuccessful());
        $this->assertStringContainsString('Incomplete data', $result->getMessage());
    }

    /**
     * @param AuthenticatorResponse $mockResponse
     * @param Result $expectedResult
     * @param callable $responseValidatorMockCallback
     */
    #[DataProvider('verifyProvider')]
    public function testVerify(
        $mockResponse,
        $expectedResult,
        ?callable $responseValidatorMockCallback = null
    ) {
        /** @var VerifyHandler&MockObject $handlerMock */
        $handlerMock = $this->getMockBuilder(VerifyHandler::class)
            ->onlyMethods(['getSerializer', 'getAuthenticatorAssertionResponseValidator'])
            ->getMock();

        // webauthn-lib 5: check() returns the updated CredentialRecord, which verify() saves
        $responseValidatorMock = $this->createMock(AuthenticatorAssertionResponseValidator::class);
        $responseValidatorMock->method('check')->willReturn(static::createTestRecord());

        // Allow the data provider to customise the validation check handling
        if ($responseValidatorMockCallback) {
            $responseValidatorMockCallback($responseValidatorMock);
        }
        $handlerMock->expects($this->any())->method('getAuthenticatorAssertionResponseValidator')
            ->willReturn($responseValidatorMock);

        $loggerMock = $this->createMock(LoggerInterface::class);
        $handlerMock->setLogger($loggerMock);

        // webauthn-lib 5 reads the credential through a serializer (PublicKeyCredentialLoader is gone)
        $serializerMock = $this->createMock(SerializerInterface::class);
        $handlerMock->expects($this->once())->method('getSerializer')->willReturn($serializerMock);

        $credentials = base64_encode(json_encode(['response' => ['authenticatorData' => 'foo']]));

        // PublicKeyCredential exposes rawId and response as properties, so a real one carries the mock response. Its
        // raw ID is that of the stored credential (setUp()): webauthn-lib 5 takes the stored record itself, which
        // verify() now looks up by that ID (webauthn-lib 4 did the lookup inside the mocked validator)
        $serializerMock->expects($this->once())->method('deserialize')
            ->with(base64_decode($credentials), PublicKeyCredential::class, 'json')
            ->willReturn(PublicKeyCredential::create('public-key', 'publicKeyCredentialId', $mockResponse));

        $this->request->setBody(json_encode(['credentials' => $credentials]));
        $result = $handlerMock->verify($this->request, $this->store, $this->registeredMethod);

        $this->assertSame($expectedResult->isSuccessful(), $result->isSuccessful());
        if ($expectedResult->getMessage()) {
            $expected = $expectedResult->getMessage();
            $actual = $result->getMessage();
            $this->assertStringContainsString($expectedResult->getMessage(), $result->getMessage());
        }
    }

    /**
     * Some centralised or reusable logic for testVerify. Note that some of the mocks are only used in some of the
     * provided data scenarios, but any expected call numbers are based on all scenarios being run.
     *
     * @return array[]
     */
    public static function verifyProvider()
    {
        $testCase = new VerifyHandlerTest('MyTestCase');
        return [
            'wrong response return type' => [
                // Deliberately the wrong child implementation of \Webauthn\AuthenticatorResponse
                $testCase->createMock(AuthenticatorAttestationResponse::class),
                new Result(false, 'Unexpected response type found'),
            ],
            'valid response' => [
                $testCase->createMock(AuthenticatorAssertionResponse::class),
                new Result(true),
                function (MockObject $responseValidatorMock) use ($testCase) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock
                        ->expects($testCase->once())
                        ->method('check')
                        ->willReturn(static::createTestRecord());
                },
            ],
            'invalid response' => [
                $testCase->createMock(AuthenticatorAssertionResponse::class),
                new Result(false, 'I am a test'),
                function (MockObject $responseValidatorMock) use ($testCase) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($testCase->once())->method('check')
                        ->willThrowException(new Exception('I am a test'));
                },
            ],
        ];
    }

    /**
    */
    #[DataProvider('provideMakeAuthenticatorDataBase64UrlSafe')]
    public function testMakeAuthenticatorDataBase64UrlSafe(array $data, string $expected, bool $exception)
    {
        $reflector = new \ReflectionClass(VerifyHandler::class);
        $method = $reflector->getMethod('makeAuthenticatorDataBase64UrlSafe');
        $method->setAccessible(true);
        $instance = new VerifyHandler();
        if ($exception) {
            $this->expectException(ResponseDataException::class);
            $method->invokeArgs($instance, [$data]);
        } else {
            $newData = $method->invokeArgs($instance, [$data]);
            $decoded = base64_decode($newData['credentials']);
            $json = json_decode($decoded, true);
            $actual = $json['response']['authenticatorData'];
            $this->assertSame($expected, $actual);
        }
    }

    public static function provideMakeAuthenticatorDataBase64UrlSafe(): array
    {
        $makeData = function ($authenticatorData) {
            $a = [];
            $a['response'] = [];
            $a['response']['authenticatorData'] = $authenticatorData;
            $jsonEncoded = json_encode($a, JSON_UNESCAPED_SLASHES);
            return ['credentials' => base64_encode($jsonEncoded)];
        };
        return [
            'invalid data' => [
                'data' => [],
                'expected' => '',
                'exception' => true,
            ],
            'change none' => [
                'data' => $makeData('abcdefghi'),
                'expected' => 'abcdefghi',
                'exception' => false,
            ],
            'change plus' => [
                'data' => $makeData('abc+def_ghi'),
                'expected' => 'abc-def_ghi',
                'exception' => false,
            ],
            'change slash' => [
                'data' => $makeData('abc-def/ghi'),
                'expected' => 'abc-def_ghi',
                'exception' => false,
            ],
            'change plus and slash' => [
                'data' => $makeData('abc+def/ghi'),
                'expected' => 'abc-def_ghi',
                'exception' => false,
            ],
        ];
    }

    /**
     * The credential stored in setUp() (raw values of its base64 fields), as the validator returns it after a login.
     * PublicKeyCredentialSource is deprecated in webauthn-lib 5.3, so this is a CredentialRecord.
     */
    protected static function createTestRecord(): CredentialRecord
    {
        return CredentialRecord::create(
            'publicKeyCredentialId',
            'public-key',
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'),
            'publicKey',
            'userHandle',
            123456790
        );
    }
}
