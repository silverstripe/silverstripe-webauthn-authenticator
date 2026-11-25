<?php

declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use CBOR\Decoder;
use Cose\Algorithm\Manager;
use Exception;
use TypeError;
use GuzzleHttp\Psr7\ServerRequest;
use Psr\Log\LoggerInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\MFA\Exception\AuthenticationFailedException;
use SilverStripe\MFA\Method\Handler\VerifyHandlerInterface;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\StoreInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Error;

class VerifyHandler implements VerifyHandlerInterface
{
    use BaseHandlerTrait;
    use CredentialRepositoryProviderTrait;

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
     * @return VerifyHandler
     */
    public function setLogger(?LoggerInterface $logger): VerifyHandler
    {
        $this->logger = $logger;
        return $this;
    }

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
            # webauthn-lib 5 options are not JsonSerializable; normalise them to the JSON the browser expects,
            # without null members (they would reach navigator.credentials as the string "null")
            'publicKey' => $this->getSerializer($this->getAttestationStatementSupportManager())
                ->normalize(
                    $this->getCredentialRequestOptions($store, $method, true),
                    'json',
                    [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]
                ),
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
            $data = $this->makeAuthenticatorDataBase64UrlSafe($data);

            $attestationStatementSupportManager = $this->getAttestationStatementSupportManager();
            $publicKeyCredential = $this->getSerializer($attestationStatementSupportManager)->deserialize(
                base64_decode($data['credentials'] ?? ''),
                PublicKeyCredential::class,
                'json'
            );
            $response = $publicKeyCredential->response;
            if (!$response instanceof AuthenticatorAssertionResponse) {
                throw new ResponseTypeException('Unexpected response type found');
            }

            // Create a PSR-7 request
            $psrRequest = ServerRequest::fromGlobals();

            # webauthn-lib 5 takes the stored credential itself rather than its ID plus a repository
            $credentialRepository = $this->getCredentialRepository($store, $registeredMethod);
            $credentialRecord = $credentialRepository->findOneByCredentialId($publicKeyCredential->rawId);
            if (!$credentialRecord) {
                throw new ResponseDataException('Unknown credential');
            }

            $updatedRecord = $this->getAuthenticatorAssertionResponseValidator($store)
                ->check(
                    $credentialRecord,
                    $response,
                    $this->getCredentialRequestOptions($store, $registeredMethod),
                    $psrRequest->getUri()->getHost(),
                    (string) $store->getMember()->ID
                );
            # webauthn-lib 4 saved the updated signature counter to the repository itself; webauthn-lib 5 returns it
            $credentialRepository->saveCredentialSource($updatedRecord);
        # webauthn-lib 5's strict denormalizers throw TypeError on badly typed input: a failed result, as with 4.x
        } catch (Exception | TypeError $e) {
            $this->logger->error($e->getMessage());
            return Result::create(false, 'Verification failed: ' . $e->getMessage());
        }

        return Result::create();
    }

    /**
     * Make authenticatorData Base64urlSafe which is expected by PublicKeyCredentialLoader::createResponse()
     * (webauthn-lib 4; in webauthn-lib 5 by AuthenticatorAssertionResponseDenormalizer)
     *
     * webauthn-lib 5 (AuthenticatorAssertionResponseDenormalizer) also requires base64url for signature, userHandle
     * and clientDataJSON, while the client (client/src/lib/convert.js byteArrayToBase64()) sends standard base64.
     * The conversion is lossless, so those fields are converted as well.
     */
    private function makeAuthenticatorDataBase64UrlSafe(array $data): array
    {
        try {
            if (!array_key_exists('credentials', $data)) {
                // this wil be immediately caught in the catch block below()
                throw new Exception();
            }
            $decodedCredentials = base64_decode($data['credentials']);
            $jsonCredientials = json_decode($decodedCredentials, true);
            $jsonCredientials['response']['authenticatorData'] = str_replace(
                ['+', '/', '='],
                ['-', '_', ''],
                $jsonCredientials['response']['authenticatorData']
            );
            foreach (['signature', 'userHandle', 'clientDataJSON'] as $field) {
                if (isset($jsonCredientials['response'][$field]) && is_string($jsonCredientials['response'][$field])) {
                    $jsonCredientials['response'][$field] = str_replace(
                        ['+', '/', '='],
                        ['-', '_', ''],
                        $jsonCredientials['response'][$field]
                    );
                }
            }
            $decodedCredentials = json_encode($jsonCredientials, JSON_UNESCAPED_SLASHES);
            $data['credentials'] = base64_encode($decodedCredentials);
            return $data;
        } catch (Exception) {
            throw new ResponseDataException('Incomplete data, required information missing');
        }
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
     * @param RegisteredMethod|null $registeredMethod
     * @param bool $reset
     * @return PublicKeyCredentialRequestOptions
     * @throws AuthenticationFailedException
     * @throws Exception
     */
    protected function getCredentialRequestOptions(
        StoreInterface $store,
        ?RegisteredMethod $registeredMethod = null,
        $reset = false
    ): PublicKeyCredentialRequestOptions {
        $state = $store->getState();

        if (
            !$reset &&
            isset($state['credentialOptions']) &&
            $state['credentialOptions'] instanceof PublicKeyCredentialRequestOptions
        ) {
            return $state['credentialOptions'];
        }

        // Use the interface methods (despite the fact the "repository" is per-member in this module)
        $validCredentials = $this->getCredentialRepository($store, $registeredMethod)
            ->findAllForUserEntity($this->getUserEntity($store->getMember()));

        if (!count($validCredentials ?? [])) {
            throw new AuthenticationFailedException('User does not appear to have any credentials loaded for webauthn');
        }

        $descriptors = array_map(function (CredentialRecord $source) {
            return $source->getPublicKeyCredentialDescriptor();
        }, $validCredentials ?? []);

        # webauthn-lib 5 options are immutable: everything the setters of webauthn-lib 4 set goes into create()
        $options = PublicKeyCredentialRequestOptions::create(
            (string) random_bytes(32),
            allowCredentials: array_values($descriptors),
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            timeout: 40000
        );

        // Persist the options for later
        $store->addState(['credentialOptions' => $options]);

        return $options;
    }

    /**
     * @param StoreInterface $store
     * @return AuthenticatorAssertionResponseValidator
     */
    protected function getAuthenticatorAssertionResponseValidator(
        StoreInterface $store
    ): AuthenticatorAssertionResponseValidator {
        # ES256 only, as with webauthn-lib 4 (registration offers ES256 only); webauthn-lib 5 would also allow RS256
        $manager = Manager::create()->add(ES256::create());
        $factory = $this->getCeremonyStepManagerFactory($this->getAttestationStatementSupportManager());
        $factory->setAlgorithmManager($manager);
        return AuthenticatorAssertionResponseValidator::create($factory->requestCeremony());
    }
}
