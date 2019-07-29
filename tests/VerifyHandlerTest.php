<?php

namespace SilverStripe\WebAuthn\Tests;

use Exception;
use Injector;
use Member;
use MFARegisteredMethod as RegisteredMethod;
use PHPUnit_Framework_MockObject_MockObject;
use SapphireTest;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\SessionStore;
use SilverStripe\WebAuthn\VerifyHandler;
use SS_HTTPRequest;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialLoader;

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
     * @var SS_HTTPRequest
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

    public function setUp()
    {
        parent::setUp();

        $this->request = new SS_HTTPRequest('GET', '/');
        $this->handler = Injector::inst()->create(VerifyHandler::class);

        $memberID = $this->logInWithPermission();
        /** @var Member $member */
        $this->member = Member::get()->byID($memberID);

        $this->store = new SessionStore($this->member);

        $this->registeredMethod = new RegisteredMethod();
        $this->registeredMethod->Data = json_encode([
            'descriptor' => [
                'type' => 'public-key',
                'id' => '7lE6zdHESCF3/qSijHVuTwlTNi/yZSD/XP6Nm6HBI8YLA0uzPqyU4U4RxyZyuKXEPiIENEr509TekP2mDKrFoQ=='
            ],
            'data' => [
                'aaguid' => 'AAAAAAAAAAAAAAAAAAAAAA==',
                'credentialId' => '7lE6zdHESCF3/qSijHVuTwlTNi/yZSD/XP6Nm6HBI8YLPiIENEr509TekP2mDKrFoQ==',
                'credentialPublicKey' => 'pU4vyn6OmHbdDyx7nWsJD+/2CycZkGzJ1u3TVj+c='
            ],
            'counter' => null,
        ]);
    }

    /**
     * @expectedException \Assert\InvalidArgumentException
     */
    public function testStartThrowsExceptionWithMissingData()
    {
        $this->registeredMethod->Data = null;
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
        $this->assertContains('Incomplete data', $result->getMessage());
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
        /** @var VerifyHandler&PHPUnit_Framework_MockObject_MockObject $handlerMock */
        $handlerMock = $this->getMockBuilder(VerifyHandler::class)
            ->setMethods(['getPublicKeyCredentialLoader', 'getAuthenticatorAssertionResponseValidator'])
            ->getMock();

        $responseValidatorMock = $this->createMock(AuthenticatorAssertionResponseValidator::class);
        // Allow the data provider to customise the validation check handling
        if ($responseValidatorMockCallback) {
            $responseValidatorMockCallback($responseValidatorMock);
        }
        $handlerMock->expects($this->any())->method('getAuthenticatorAssertionResponseValidator')
            ->willReturn($responseValidatorMock);

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
            $this->assertContains($expectedResult->getMessage(), $result->getMessage());
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
                function (PHPUnit_Framework_MockObject_MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($this->once())->method('check')->willReturn(true);
                },
            ],
            'invalid response' => [
                $this->createMock(AuthenticatorAssertionResponse::class),
                new Result(false, 'I am a test'),
                function (PHPUnit_Framework_MockObject_MockObject $responseValidatorMock) {
                    // Specifically setting expectations for the result of the response validator's "check" call
                    $responseValidatorMock->expects($this->once())->method('check')
                        ->willThrowException(new Exception('I am a test'));
                },
            ],
        ];
    }
}
