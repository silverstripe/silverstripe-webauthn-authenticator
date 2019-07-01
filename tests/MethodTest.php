<?php

namespace SilverStripe\WebAuthn\Tests;

use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\View\Requirements;
use SilverStripe\WebAuthn\Method;
use SilverStripe\WebAuthn\RegisterHandler;
use SilverStripe\WebAuthn\VerifyHandler;

class MethodTest extends SapphireTest
{
    public function testGetURLSegment()
    {
        $method = new Method();
        $this->assertSame('web-authn', $method->getURLSegment());
    }

    public function testGetVerifyHandler()
    {
        $method = new Method();
        $this->assertInstanceOf(VerifyHandler::class, $method->getVerifyHandler());
    }

    public function testGetRegisterHandler()
    {
        $method = new Method();
        $this->assertInstanceOf(RegisterHandler::class, $method->getRegisterHandler());
    }

    public function testGetThumbnail()
    {
        $method = new Method();
        $this->assertContains('images/securityKey.svg', $method->getThumbnail());
    }

    public function testApplyRequirements()
    {
        Requirements::clear();
        $method = new Method();
        $method->applyRequirements();

        $this->assertCount(1, Requirements::backend()->getJavascript());
        $this->assertCount(1, Requirements::backend()->getCSS());
    }

    public function testIsAvailableUnderHttps()
    {
        $method = new Method();
        Director::config()->set('alternate_base_url', 'https://mywebsite.com');
        $this->assertTrue($method->isAvailable());
    }

    public function testIsNotAvailableUnderHttp()
    {
        $method = new Method();
        Director::config()->set('alternate_base_url', 'http://mywebsite.com');
        $this->assertFalse($method->isAvailable());
    }

    public function testGetUnavailableMessage()
    {
        $method = new Method();
        $this->assertContains('can only be used over HTTPS', $method->getUnavailableMessage());
    }
}
