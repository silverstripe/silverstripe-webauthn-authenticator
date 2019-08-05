<?php declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use CBOR\Decoder;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use MFARegisteredMethod as RegisteredMethod;
use SilverStripe\MFA\Exception\AuthenticationFailedException;
use SilverStripe\MFA\Method\Handler\VerifyHandlerInterface;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\StoreInterface;
use SS_HTTPRequest;
use SS_Log;
use SS_Object;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

class VerifyHandler extends SS_Object implements VerifyHandlerInterface
{
    use BaseHandlerTrait;
    use CredentialRepositoryProviderTrait;

    /**
     * Stores any data required to handle a log in process with a method, and returns relevant state to be applied to
     * the front-end application managing the process.
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
     * @param SS_HTTPRequest $request
     * @param StoreInterface $store
     * @param RegisteredMethod $registeredMethod The RegisteredMethod instance that is being verified
     * @return Result
     */
    public function verify(SS_HTTPRequest $request, StoreInterface $store, RegisteredMethod $registeredMethod): Result
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

            $this->getAuthenticatorAssertionResponseValidator($decoder, $store)
                ->check(
                    $publicKeyCredential->getRawId(),
                    $response,
                    $this->getCredentialRequestOptions($store, $registeredMethod),
                    $psrRequest,
                    (string) $store->getMember()->ID
                );
        } catch (Exception $e) {
            SS_Log::log($e, SS_Log::ERR);
            return Result::create(false, 'Verification failed: ' . $e->getMessage());
        }

        return Result::create();
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
        RegisteredMethod $registeredMethod = null,
        $reset = false
    ): PublicKeyCredentialRequestOptions {
        $state = $store->getState();

        if (!$reset && !empty($state) && !empty($state['credentialOptions'])) {
            return PublicKeyCredentialRequestOptions::createFromArray($state['credentialOptions']);
        }

        // Use the interface methods (despite the fact the "repository" is per-member in this module)
        $validCredentials = $this->getCredentialRepository($store, $registeredMethod)
            ->findAllForUserEntity($this->getUserEntity($store->getMember()));

        if (!count($validCredentials)) {
            throw new AuthenticationFailedException('User does not appear to have any credentials loaded for webauthn');
        }

        $descriptors = array_map(function(PublicKeyCredentialSource $source) {
            return $source->getPublicKeyCredentialDescriptor();
        }, $validCredentials);

        $options = new PublicKeyCredentialRequestOptions(
            random_bytes(32),
            40000,
            null,
            $descriptors,
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED
        );

        // Persist the options for later
        $store->addState(['credentialOptions' => $options]);

        return $options;
    }

    /**
     * @param Decoder $decoder
     * @param StoreInterface $store
     * @return AuthenticatorAssertionResponseValidator
     */
    protected function getAuthenticatorAssertionResponseValidator(
        Decoder $decoder,
        StoreInterface $store
    ): AuthenticatorAssertionResponseValidator {
        return new AuthenticatorAssertionResponseValidator(
            $this->getCredentialRepository($store),
            $decoder,
            new TokenBindingNotSupportedHandler(),
            new ExtensionOutputCheckerHandler()
        );
    }
}
