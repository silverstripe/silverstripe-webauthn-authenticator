<?php declare(strict_types=1);

namespace SilverStripe\WebAuthn;

use SilverStripe\Control\Director;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Core\Manifest\ModuleLoader;
use SilverStripe\MFA\Method\Handler\VerifyHandlerInterface;
use SilverStripe\MFA\Method\Handler\RegisterHandlerInterface;
use SilverStripe\MFA\Method\MethodInterface;
use SilverStripe\View\Requirements;

class Method implements MethodInterface
{
    /**
     * Get a URL segment for this method. This will be used in URL paths for performing authentication by this method
     *
     * @return string
     */
    public function getURLSegment(): string
    {
        return 'web-authn';
    }

    /**
     * Return the VerifyLHandler that is used to start and verify log in attempts with this method
     *
     * @return VerifyHandlerInterface
     */
    public function getVerifyHandler(): VerifyHandlerInterface
    {
        return Injector::inst()->create(VerifyHandler::class);
    }

    /**
     * Return the RegisterHandler that is used to perform registrations with this method
     *
     * @return RegisterHandlerInterface
     */
    public function getRegisterHandler(): RegisterHandlerInterface
    {
        return Injector::inst()->create(RegisterHandler::class);
    }

    /**
     * Return a URL to an image to be used as a thumbnail in the MFA verification/registration grid for all MFA methods
     *
     * @return string
     */
    public function getThumbnail(): string
    {
        return (string) ModuleLoader::getModule('silverstripe/webauthn-authenticator')
            ->getResource('client/dist/images/securityKey.svg')
            ->getURL();
    }

    /**
     * Leverage the Requirements API to ensure client requirements are included. This is called just after the base
     * module requirements are specified
     *
     * @return void
     */
    public function applyRequirements(): void
    {
        Requirements::javascript('silverstripe/webauthn-authenticator: client/dist/js/bundle.js');
        Requirements::css('silverstripe/webauthn-authenticator: client/dist/styles/bundle.css');
    }

    public function isAvailable(): bool
    {
        return Director::is_https();
    }

    public function getUnavailableMessage(): string
    {
        return _t(__CLASS__ . '.REQUIRES_HTTPS', 'This method can only be used over HTTPS.');
    }
}
