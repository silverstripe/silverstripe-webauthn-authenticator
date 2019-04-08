<?php declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Extensible;
use SilverStripe\MFA\Method\Handler\RegisterHandlerInterface;
use SilverStripe\MFA\Store\StoreInterface;
use SilverStripe\Security\Member;
use SilverStripe\SiteConfig\SiteConfig;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

class RegisterHandler implements RegisterHandlerInterface
{
    use Extensible;
    use Configurable;

    /**
     * Provide a user help link that will be available when registering backup codes
     * TODO Will this have a user help link as a default?
     *
     * @config
     * @var string
     */
    private static $user_help_link;

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
        $options = $this->getCredentialCreationOptions($store);

        return [
            'keyData' => $options,
        ];
    }

    /**
     * Confirm that the provided details are valid, and create a new RegisteredMethod against the member.
     *
     * @param HTTPRequest $request
     * @param StoreInterface $store
     * @return array
     * @throws Exception
     */
    public function register(HTTPRequest $request, StoreInterface $store): array
    {
        $options = $this->getCredentialCreationOptions($store);
        $data = json_decode($request->getBody(), true);

        // CBOR
        $decoder = new Decoder(new TagObjectManager(), new OtherObjectManager());

        // Attestation statement support manager
        $attestationStatementSupportManager = new AttestationStatementSupportManager();
        $attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
        $attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport($decoder));

        // Attestation object loader
        $attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager, $decoder);

        $publicKeyCredentailLoader = new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);

        $credentialRepository = new CredentialRepository($store->getMember());

        $authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
            $attestationStatementSupportManager,
            $credentialRepository,
            new TokenBindingNotSupportedHandler(),
            new ExtensionOutputCheckerHandler()
        );

        // Create a PSR-7 request
        $request = ServerRequest::fromGlobals();

        try {
            $publicKeyCredential = $publicKeyCredentailLoader->load(base64_decode($data['credentials']));
            $response = $publicKeyCredential->getResponse();

            if (!$response instanceof AuthenticatorAttestationResponse) {
                die('why even have this?');
            }

            $authenticatorAttestationResponseValidator->check($response, $options, $request);
        } catch (\Exception $e) {
            var_dump($e);
            die('do something here: '.$e->getMessage());
        }

        if (!$response->getAttestationObject()->getAuthData()->hasAttestedCredentialData()) {
            die('something else that might go wrong but probably wont');
        }

        return [
            'descriptor' => $publicKeyCredential->getPublicKeyCredentialDescriptor(),
            'data' => $response->getAttestationObject()->getAuthData()->getAttestedCredentialData(),
            'counter' => null,
        ];
    }

    /**
     * Provide a localised name for this MFA Method.
     *
     * eg. "Authenticator app"
     *
     * @return string
     */
    public function getName(): string
    {
        return _t(__CLASS__ . '.NAME', 'Register your security key');
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
        return static::config()->get('user_help_link') ?: '';
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

    public function isAvailable(): bool
    {
        return Director::is_https();
    }

    public function getUnavailableMessage(): string
    {
        return _t(__CLASS__ . '.REQUIRES_HTTPS', 'This method can only be used over HTTPS.');
    }

    protected function getRelyingPartyEntity()
    {
        return new PublicKeyCredentialRpEntity(
            (string) SiteConfig::current_site_config()->Title,
            /*Environment::getEnv('SS_BASE_URL') ?:*/ null,
            static::config()->get('application_logo')
        );
    }

    protected function getUserEntity(Member $member)
    {
        return new PublicKeyCredentialUserEntity(
            $member->getName(),
            $member->ID,
            $member->getName()
        );
    }

    /**
     * @param StoreInterface $store
     * @return PublicKeyCredentialCreationOptions
     * @throws Exception
     */
    protected function getCredentialCreationOptions(StoreInterface $store): PublicKeyCredentialCreationOptions
    {
        $state = $store->getState();

        if (empty($state) || empty($state['challenge'])) {
            $challenge = random_bytes(32);
            $store->setState(['challenge' => $challenge]);
        } else {
            $challenge = $state['challenge'];
        }

        return new PublicKeyCredentialCreationOptions(
            $this->getRelyingPartyEntity(),
            $this->getUserEntity($store->getMember()),
            $challenge,
            [new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256)],
            40000,
            [],
            new AuthenticatorSelectionCriteria(),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            new AuthenticationExtensionsClientInputs()
        );
    }
}
