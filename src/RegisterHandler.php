<?php declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use Cose\Algorithms;
use Director;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use SilverStripe\MFA\Method\Handler\RegisterHandlerInterface;
use SilverStripe\MFA\State\Result;
use SilverStripe\MFA\Store\StoreInterface;
use SiteConfig;
use SS_HTTPRequest;
use SS_Log;
use SS_Object;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

class RegisterHandler extends SS_Object implements RegisterHandlerInterface
{
    use BaseHandlerTrait;
    use CredentialRepositoryProviderTrait;

    /**
     * Provide a user help link that will be available when registering backup codes
     *
     * @config
     * @var string
     */
    private static $user_help_link = 'https://userhelp.silverstripe.org/en/4/optional_features/multi-factor_authentication/user_manual/using_security_keys/'; // phpcs-disable-line

    /**
     * The default attachment mode to use for Authentication Selection Criteria.
     * SilverStripe 3's manifest parser requires the full namespace to be set here.
     *
     * See {@link getAuthenticatorSelectionCriteria()} for more information.
     *
     * @config
     * @var string
     */
    private static $authenticator_attachment =
        \Webauthn\AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;

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
            'keyData' => $options,
        ];
    }

    /**
     * Confirm that the provided details are valid, and create a new RegisteredMethod against the member.
     *
     * @param SS_HTTPRequest $request
     * @param StoreInterface $store
     * @return Result
     * @throws Exception
     */
    public function register(SS_HTTPRequest $request, StoreInterface $store): Result
    {
        $options = $this->getCredentialCreationOptions($store);
        $data = json_decode((string) $request->getBody(), true);

        try {
            if (empty($data['credentials'])) {
                throw new ResponseDataException('Incomplete data, required information missing');
            }

            $decoder = $this->getDecoder();
            $attestationStatementSupportManager = $this->getAttestationStatementSupportManager($decoder);
            $attestationObjectLoader = $this->getAttestationObjectLoader($attestationStatementSupportManager, $decoder);
            $publicKeyCredentialLoader = $this->getPublicKeyCredentialLoader($attestationObjectLoader, $decoder);
            $publicKeyCredential = $publicKeyCredentialLoader->load(base64_decode($data['credentials']));
            $response = $publicKeyCredential->getResponse();

            if (!$response instanceof AuthenticatorAttestationResponse) {
                throw new ResponseTypeException('Unexpected response type found');
            }

            if (!$response->getAttestationObject()->getAuthData()->hasAttestedCredentialData()) {
                throw new ResponseDataException('Incomplete data, required information missing');
            }

            // Create a PSR-7 request
            $psrRequest = ServerRequest::fromGlobals();

            // Validate the webauthn response
            $this->getAuthenticatorAttestationResponseValidator($attestationStatementSupportManager, $store)
                ->check($response, $options, $psrRequest);
        } catch (Exception $e) {
            SS_Log::log($e, SS_Log::ERR);
            return Result::create(false, 'Registration failed: ' . $e->getMessage());
        }

        $credentialRepository = $this->getCredentialRepository($store);

        $source = PublicKeyCredentialSource::createFromPublicKeyCredential(
            $publicKeyCredential,
            $options->getUser()->getId()
        );

        // Clear the repository so only one key is registered at a time
        // NOTE: This can be considered temporary behaviour until the UI supports managing multiple keys
        $credentialRepository->reset();

        // Persist the "credential source"
        $credentialRepository->saveCredentialSource($source);

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
        $credentialRepository = $this->getCredentialRepository($store);

        return new AuthenticatorAttestationResponseValidator(
            $attestationStatementSupportManager,
            $credentialRepository,
            new TokenBindingNotSupportedHandler(),
            new ExtensionOutputCheckerHandler()
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
        $host = parse_url(Director::protocolAndHost(), PHP_URL_HOST);

        return new PublicKeyCredentialRpEntity(
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

        if (!$reset && !empty($state) && !empty($state['credentialOptions'])) {
            return PublicKeyCredentialCreationOptions::createFromArray($state['credentialOptions']);
        }

        $credentialOptions = new PublicKeyCredentialCreationOptions(
            $this->getRelyingPartyEntity(),
            $this->getUserEntity($store->getMember()),
            random_bytes(32),
            [new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256)],
            40000,
            [],
            $this->getAuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            new AuthenticationExtensionsClientInputs()
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
        return new AuthenticatorSelectionCriteria(
            (string) $this->config()->get('authenticator_attachment')
        );
    }
}
