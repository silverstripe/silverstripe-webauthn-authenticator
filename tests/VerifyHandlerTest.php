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
use Webauthn\AuthenticatorResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

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
     * @dataProvider verifyProvider
     */
    public function testVerify(
        $mockResponse,
        $expectedResult,
        callable $responseValidatorMockCallback = null
    ) {
        /** @var VerifyHandler&MockObject $handlerMock */
        $handlerMock = $this->getMockBuilder(VerifyHandler::class)
            ->setMethods(['getPublicKeyCredentialLoader', 'getAuthenticatorAssertionResponseValidator'])
            ->getMock();

        $publicKeyCredentialSourceMock = $this->createMock(PublicKeyCredentialSource::class);
        $responseValidatorMock = $this->createMock(AuthenticatorAssertionResponseValidator::class);
        $responseValidatorMock->method('check')->willReturn($publicKeyCredentialSourceMock);

        // Allow the data provider to customise the validation check handling
        if ($responseValidatorMockCallback) {
            $responseValidatorMockCallback($responseValidatorMock);
        }
        $handlerMock->expects($this->any())->method('getAuthenticatorAssertionResponseValidator')
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
        $result = $handlerMock->verify($this->request, $this->store, $this->registeredMethod);

        $this->assertSame($expectedResult->isSuccessful(), $result->isSuccessful());
        if ($expectedResult->getMessage()) {
            $this->assertStringContainsString($expectedResult->getMessage(), $result->getMessage());
        }
    }

    /**
     * Some centralised or reusable logic for testVerify. Note that some of the mocks are only used in some of the
     * provided data scenarios, but any expected call numbers are based on all scenarios being run.
     *
     * @return array[]
     */
    public function verifyProvider()
    {
        return [
            'wrong response return type' => [
                // Deliberately the wrong child implementation of \Webauthn\AuthenticatorResponse
                $this->createMock(AuthenticatorAttestationResponse::class),
                new Result(false, 'Unexpected response type found'),
            ],
            'valid response' => [
                $this->createMock(AuthenticatorAssertionResponse::class),
                new Result(true),
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
            'invalid response' => [
                $this->createMock(AuthenticatorAssertionResponse::class),
                new Result(false, 'I am a test'),
                function (MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($this->once())->method('check')
                        ->willThrowException(new Exception('I am a test'));
                },
            ],
        ];
    }
}
