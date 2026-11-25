<?php

declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use Cose\Algorithms;
use Exception;
use TypeError;
use GuzzleHttp\Psr7\ServerRequest;
use Psr\Log\LoggerInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Extensible;
use SilverStripe\MFA\Method\Handler\RegisterHandlerInterface;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\StoreInterface;
use SilverStripe\SiteConfig\SiteConfig;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRpEntity;

class RegisterHandler implements RegisterHandlerInterface
{
    use BaseHandlerTrait;
    use Extensible;
    use Configurable;
    use CredentialRepositoryProviderTrait;

    /**
     * Provide a user help link that will be available when registering backup codes
     *
     * @config
     * @var string
     */
    private static $user_help_link = 'https://userhelp.silverstripe.org/en/6/optional_features/mfa/user_manual/using_security_keys/'; // phpcs:ignore

    /**
     * The default attachment mode to use for Authentication Selection Criteria.
     *
     * See {@link getAuthenticatorSelectionCriteria()} for more information.
     *
     * @config
     * @var string
     */
    private static $authenticator_attachment = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;

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
    protected $logger = null;

    /**
     * Sets the {@see $logger} member variable
     *
     * @param LoggerInterface|null $logger
     * @return RegisterHandler
     */
    public function setLogger(?LoggerInterface $logger): RegisterHandler
    {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Stores any data required to handle a registration process with a method, and returns relevant state to be applied
     * to the front-end application managing the process.
     *
     * @param StoreInterface $store An object that hold session data (and the Member) that can be mutated
     * @return array Props to be passed to a front-end component
     * @throws Exception When there is no valid source of CSPRNG
     */
    public function start(StoreInterface $store): array
    {
        $options = $this->getCredentialCreationOptions($store, true);

        return [
            # webauthn-lib 5 options are not JsonSerializable; normalise them to the JSON the browser expects,
            # without null members (they would reach navigator.credentials as the string "null")
            'keyData' => $this->getSerializer($this->getAttestationStatementSupportManager())
                ->normalize($options, 'json', [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]),
        ];
    }

    /**
     * Confirm that the provided details are valid, and create a new RegisteredMethod against the member.
     *
     * @param HTTPRequest $request
     * @param StoreInterface $store
     * @return Result
     * @throws Exception
     */
    public function register(HTTPRequest $request, StoreInterface $store): Result
    {
        $options = $this->getCredentialCreationOptions($store);
        $data = json_decode((string) $request->getBody(), true);
        $publicKeyCredentialSource = null;

        try {
            if (empty($data['credentials'])) {
                throw new ResponseDataException('Incomplete data, required information missing');
            }

            $attestationStatementSupportManager = $this->getAttestationStatementSupportManager();
            $publicKeyCredential = $this->getSerializer($attestationStatementSupportManager)->deserialize(
                base64_decode($data['credentials'] ?? ''),
                PublicKeyCredential::class,
                'json'
            );
            $response = $publicKeyCredential->response;

            if (!$response instanceof AuthenticatorAttestationResponse) {
                throw new ResponseTypeException('Unexpected response type found');
            }

            if (!$response->attestationObject->authData->hasAttestedCredentialData()) {
                throw new ResponseDataException('Incomplete data, required information missing');
            }

            // Create a PSR-7 request
            $psrRequest = ServerRequest::fromGlobals();

            // Validate the webauthn response
            $publicKeyCredentialSource = $this
                ->getAuthenticatorAttestationResponseValidator($attestationStatementSupportManager, $store)
                ->check($response, $options, $psrRequest->getUri()->getHost());

            # webauthn-lib 4.4 refused a credential ID the repository already held (4.9 had dropped that check);
            # webauthn-lib 5 leaves it to the application
            # (https://www.w3.org/TR/webauthn-3/#reg-ceremony-verify-credential-id)
            if ($this->getCredentialRepository($store)->has($publicKeyCredentialSource->publicKeyCredentialId)) {
                throw new ResponseDataException('The credential ID is already registered');
            }
        # webauthn-lib 5's strict denormalizers throw TypeError on badly typed input: a failed result, as with 4.x
        } catch (Exception | TypeError $e) {
            $this->logger->error($e->getMessage());
            return Result::create(false, 'Registration failed: ' . $e->getMessage());
        }

        $credentialRepository = $this->getCredentialRepository($store);

        // Clear the repository so only one key is registered at a time
        // NOTE: This can be considered temporary behaviour until the UI supports managing multiple keys
        $credentialRepository->reset();

        // Persist the "credential source"
        $credentialRepository->saveCredentialSource($publicKeyCredentialSource);

        return Result::create()->setContext($credentialRepository->toArray());
    }

    /**
     * @param AttestationStatementSupportManager $attestationStatementSupportManager
     * @param StoreInterface $store
     * @return AuthenticatorAttestationResponseValidator
     */
    protected function getAuthenticatorAttestationResponseValidator(
        AttestationStatementSupportManager $attestationStatementSupportManager,
        StoreInterface $store
    ): AuthenticatorAttestationResponseValidator {
        # webauthn-lib 5: no credential repository, token binding handler or extension checker arguments any more;
        # the checks are configured through the ceremony steps (BaseHandlerTrait::getCeremonyStepManagerFactory())
        return AuthenticatorAttestationResponseValidator::create(
            $this->getCeremonyStepManagerFactory($attestationStatementSupportManager)->creationCeremony()
        );
    }

    /**
     * Provide a localised description of this MFA Method.
     *
     * eg. "Verification codes are created by an app on your phone"
     *
     * @return string
     */
    public function getDescription(): string
    {
        return _t(
            __CLASS__ . '.DESCRIPTION',
            'A small USB device which is used for verifying you'
        );
    }

    /**
     * Provide a localised URL to a support article about the registration process for this MFA Method.
     *
     * @return string
     */
    public function getSupportLink(): string
    {
        return $this->config()->get('user_help_link') ?: '';
    }

    /**
     * Provide a localised string to describe the support link {@see getSupportLink} about this MFA Method.
     *
     * @return string
     */
    public function getSupportText(): string
    {
        return _t(__CLASS__ . '.SUPPORT_LINK_DESCRIPTION', 'How to use security keys.');
    }

    /**
     * Get the key that a React UI component is registered under (with @silverstripe/react-injector on the front-end)
     *
     * @return string
     */
    public function getComponent(): string
    {
        return 'WebAuthnRegister';
    }

    /**
     * @return PublicKeyCredentialRpEntity
     */
    protected function getRelyingPartyEntity(): PublicKeyCredentialRpEntity
    {
        // Relying party entity ONLY allows domains or subdomains. Remove ports or anything else that isn't already.
        // See https://github.com/web-auth/webauthn-framework/blob/v1.2.2/doc/webauthn/PublicKeyCredentialCreation.md#relying-party-entity
        $host = parse_url(Director::host() ?? '', PHP_URL_HOST);

        return PublicKeyCredentialRpEntity::create(
            (string) SiteConfig::current_site_config()->Title,
            $host,
            static::config()->get('application_logo')
        );
    }

    /**
     * @param StoreInterface $store
     * @param bool $reset
     * @return PublicKeyCredentialCreationOptions
     * @throws Exception
     */
    protected function getCredentialCreationOptions(
        StoreInterface $store,
        bool $reset = false
    ): PublicKeyCredentialCreationOptions {
        $state = $store->getState();

        if (
            !$reset &&
            isset($state['credentialOptions']) &&
            $state['credentialOptions'] instanceof PublicKeyCredentialCreationOptions
        ) {
            return $state['credentialOptions'];
        }

        # webauthn-lib 5 options are immutable: everything the setters of webauthn-lib 4 set goes into create()
        $credentialOptions = PublicKeyCredentialCreationOptions::create(
            $this->getRelyingPartyEntity(),
            $this->getUserEntity($store->getMember()),
            random_bytes(32),
            [PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES256)],
            authenticatorSelection: $this->getAuthenticatorSelectionCriteria(),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            timeout: 40000
        );

        $store->setState(['credentialOptions' => $credentialOptions] + $state);

        return $credentialOptions;
    }

    /**
     * Returns an "Authenticator Selection Criteria" object which is intended to select the appropriate authenticators
     * to participate in the creation operation.
     *
     * The default is to allow only "cross platform" authenticators, e.g. disabling "single platform" authenticators
     * such as touch ID.
     *
     * For more information: https://github.com/web-auth/webauthn-framework/blob/v1.2/doc/webauthn/PublicKeyCredentialCreation.md#authenticator-selection-criteria
     *
     * @return AuthenticatorSelectionCriteria
     */
    protected function getAuthenticatorSelectionCriteria(): AuthenticatorSelectionCriteria
    {
        # null (no preference: allow platform and cross-platform keys) must stay null: webauthn-lib 5 only accepts
        # null, 'platform' or 'cross-platform' and throws on the empty string a (string) cast would give
        return AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: $this->config()->get('authenticator_attachment') ?: null
        );
    }
}
