<?php declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use CBOR\Decoder;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\MFA\Method\Handler\VerifyHandlerInterface;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\StoreInterface;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

class VerifyHandler implements VerifyHandlerInterface
{
    use BaseHandlerTrait;

    /**
     * Dependency injection configuration
     *
     * @config
     * @var array
     */
    private static $dependencies = [
        'Logger' => '%$' . LoggerInterface::class . '.mfa',
    ];

    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Sets the {@see $logger} member variable
     *
     * @param LoggerInterface|null $logger
     * @return self
     */
    public function setLogger(?LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Stores any data required to handle a login process with a method, and returns relevant state to be applied to the
     * front-end application managing the process.
     *
     * @param StoreInterface $store An object that hold session data (and the Member) that can be mutated
     * @param RegisteredMethod $method The RegisteredMethod instance that is being verified
     * @return array Props to be passed to a front-end component
     */
    public function start(StoreInterface $store, RegisteredMethod $method): array
    {
        return [
            'publicKey' => $this->getCredentialRequestOptions($store, $method, true),
        ];
    }

    /**
     * Verify the request has provided the right information to verify the member that aligns with any sessions state
     * that may have been set prior
     *
     * @param HTTPRequest $request
     * @param StoreInterface $store
     * @param RegisteredMethod $registeredMethod The RegisteredMethod instance that is being verified
     * @return Result
     */
    public function verify(HTTPRequest $request, StoreInterface $store, RegisteredMethod $registeredMethod): Result
    {
        $data = json_decode((string) $request->getBody(), true);

        try {
            if (empty($data['credentials'])) {
                throw new ResponseDataException('Incomplete data, required information missing');
            }

            $decoder = $this->getDecoder();
            $attestationStatementSupportManager = $this->getAttestationStatementSupportManager($decoder);
            $attestationObjectLoader = $this->getAttestationObjectLoader($attestationStatementSupportManager, $decoder);
            $publicKeyCredential = $this
                ->getPublicKeyCredentialLoader($attestationObjectLoader, $decoder)
                ->load(base64_decode($data['credentials']));

            $response = $publicKeyCredential->getResponse();
            if (!$response instanceof AuthenticatorAssertionResponse) {
                throw new ResponseTypeException('Unexpected response type found');
            }

            // Create a PSR-7 request
            $psrRequest = ServerRequest::fromGlobals();

            $this->getAuthenticatorAssertionResponseValidator($decoder, $store, $registeredMethod)
                ->check(
                    $publicKeyCredential->getRawId(),
                    $response,
                    $this->getCredentialRequestOptions($store, $registeredMethod),
                    $psrRequest,
                    (string) $store->getMember()->ID
                );
        } catch (Exception $e) {
            $this->logger->error($e->getMessage());
            return Result::create(false, 'Verification failed: ' . $e->getMessage());
        }

        return Result::create();
    }

    /**
     * Provide a localised string that serves as a lead in for choosing this option for authentication
     *
     * eg. "Enter one of your recovery codes"
     *
     * @return string
     */
    public function getLeadInLabel(): string
    {
        return _t(__CLASS__ . '.LEAD_IN', 'Verify with security key');
    }

    /**
     * Get the key that a React UI component is registered under (with @silverstripe/react-injector on the front-end)
     *
     * @return string
     */
    public function getComponent(): string
    {
        return 'WebAuthnVerify';
    }

    /**
     * @param StoreInterface $store
     * @param RegisteredMethod $registeredMethod
     * @param bool $reset
     * @return PublicKeyCredentialRequestOptions
     * @throws Exception
     */
    protected function getCredentialRequestOptions(
        StoreInterface $store,
        RegisteredMethod $registeredMethod,
        $reset = false
    ): PublicKeyCredentialRequestOptions {
        $state = $store->getState();

        if (!$reset && !empty($state) && !empty($state['credentialOptions'])) {
            return PublicKeyCredentialRequestOptions::createFromArray($state['credentialOptions']);
        }

        $data = json_decode((string) $registeredMethod->Data, true) ?? [];
        $descriptor = PublicKeyCredentialDescriptor::createFromArray($data['descriptor'] ?? []);

        $options = new PublicKeyCredentialRequestOptions(
            random_bytes(32),
            40000,
            null,
            [$descriptor],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED
        );

        $state['credentialOptions'] = $options;
        $store->setState($state);

        return $options;
    }

    /**
     * @param Decoder $decoder
     * @param StoreInterface $store
     * @param RegisteredMethod $registeredMethod
     * @return AuthenticatorAssertionResponseValidator
     */
    protected function getAuthenticatorAssertionResponseValidator(
        Decoder $decoder,
        StoreInterface $store,
        RegisteredMethod $registeredMethod
    ): AuthenticatorAssertionResponseValidator {
        $credentialRepository = new CredentialRepository($store->getMember(), $registeredMethod);

        return new AuthenticatorAssertionResponseValidator(
            $credentialRepository,
            $decoder,
            new TokenBindingNotSupportedHandler(),
            new ExtensionOutputCheckerHandler()
        );
    }
}
