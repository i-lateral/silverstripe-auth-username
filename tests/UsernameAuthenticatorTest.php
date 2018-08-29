<?php

namespace ilateral\SilverStripe\AuthUsername\Tests;

use SilverStripe\Security\Member;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Security;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\LoginAttempt;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\DefaultAdminService;
use SilverStripe\Security\MemberAuthenticator\MemberLoginForm;
use ilateral\SilverStripe\AuthUsername\Security\UsernameOrEmailAuthenticator;



/**
 * Add some basic tests to the username authenticator (these expand upon
 * the default MemberAuthenticator tests) where needed.
 *
 * @package auth-username
 * @subpackage tests
 */
class UsernameAuthenticatorTest extends SapphireTest
{

	protected $usesDatabase = true;

	protected $defaultUsername = null;

	protected $defaultPassword = null;

	protected function setUp()
    {
		parent::setUp();

        if (DefaultAdminService::hasDefaultAdmin()) {
            $this->defaultUsername = DefaultAdminService::getDefaultAdminUsername();
            $this->defaultPassword = DefaultAdminService::getDefaultAdminPassword();
            DefaultAdminService::clearDefaultAdmin();
        } else {
            $this->defaultUsername = null;
            $this->defaultPassword = null;
		}

        DefaultAdminService::setDefaultAdmin('admin', 'password');
    }

    protected function tearDown()
    {
        DefaultAdminService::clearDefaultAdmin();
        if ($this->defaultUsername) {
            DefaultAdminService::setDefaultAdmin($this->defaultUsername, $this->defaultPassword);
        }
        parent::tearDown();
    }

    public function testCustomIdentifierField()
    {
        Member::config()->set('alt_identifier_field', 'Email');
        $label = Member::singleton()
            ->fieldLabel(Member::config()->get('alt_identifier_field'));
        $this->assertEquals($label, 'Email');
    }

    public function testGenerateLoginForm()
    {
        $authenticator = new UsernameOrEmailAuthenticator();
		$controller = new Security();

        // Create basic login form
        $frontendResponse = $authenticator
            ->getLoginHandler($controller->link())
            ->handleRequest(Controller::curr()->getRequest());
        $this->assertTrue(is_array($frontendResponse));
        $this->assertTrue(isset($frontendResponse['Form']));
        $this->assertTrue($frontendResponse['Form'] instanceof MemberLoginForm);
	}


    public function testDefaultAdmin()
    {
		$authenticator = new UsernameOrEmailAuthenticator();

        // Test correct login
        /** @var ValidationResult $message */
        $result = $authenticator->authenticate(
            [
            'Identity' => 'admin',
            'Password' => 'password'
            ],
            Controller::curr()->getRequest(),
            $message
        );
        $this->assertNotEmpty($result);
        $this->assertEquals($result->Email, DefaultAdminService::getDefaultAdminUsername());
        $this->assertTrue($message->isValid());
        // Test incorrect login
        $result = $authenticator->authenticate(
            [
            'Identity' => 'admin',
            'Password' => 'notmypassword'
            ],
            Controller::curr()->getRequest(),
            $message
        );
        $messages = $message->getMessages();
        $this->assertEmpty($result);
        $this->assertEquals(
            'The provided details don\'t seem to be correct. Please try again.',
            $messages[0]['message']
        );
	}
	
	public function testDefaultAdminLockOut()
    {
        $authenticator = new UsernameOrEmailAuthenticator();
        Config::modify()->set(Member::class, 'lock_out_after_incorrect_logins', 1);
        Config::modify()->set(Member::class, 'lock_out_delay_mins', 10);
        DBDatetime::set_mock_now('2016-04-18 00:00:00');
        // Test correct login
        $authenticator->authenticate(
            [
                'Identity' => 'admin',
                'Password' => 'wrongpassword'
            ],
            Controller::curr()->getRequest()
        );
        $defaultAdmin = DefaultAdminService::singleton()->findOrCreateDefaultAdmin();
        $this->assertNotNull($defaultAdmin);
        $this->assertFalse($defaultAdmin->canLogin());
        $this->assertEquals('2016-04-18 00:10:00', $defaultAdmin->LockedOutUntil);
	}

	public function testNonExistantMemberGetsLoginAttemptRecorded()
    {
        Member::config()
            ->set('lock_out_after_incorrect_logins', 1)
            ->set('lock_out_delay_mins', 10);
        $email = 'notreal@example.com';
        $this->assertFalse(Member::get()->filter(array('Email' => $email))->exists());
        $this->assertCount(0, LoginAttempt::get());
        $authenticator = new UsernameOrEmailAuthenticator();
        $result = new ValidationResult();
        $member = $authenticator->authenticate(
            [
                'Identity' => $email,
                'Password' => 'password',
            ],
            Controller::curr()->getRequest(),
            $result
        );
        $this->assertFalse($result->isValid());
        $this->assertNull($member);
        $this->assertCount(1, LoginAttempt::get());
		$attempt = LoginAttempt::get()->first();
        $this->assertEmpty($attempt->Email); // Doesn't store potentially sensitive data
		$this->assertEquals(sha1($email), $attempt->EmailHashed);
        $this->assertEquals(LoginAttempt::FAILURE, $attempt->Status);
    }

	public function testNonExistantMemberGetsLockedOut()
    {
        Member::config()
            ->set('lock_out_after_incorrect_logins', 1)
            ->set('lock_out_delay_mins', 10);
        $email = 'notreal@example.com';
        $this->assertFalse(Member::get()->filter(array('Email' => $email))->exists());
        $authenticator = new UsernameOrEmailAuthenticator();
        $result = new ValidationResult();
        $member = $authenticator->authenticate(
            [
                'Identity' => $email,
                'Password' => 'password',
            ],
            Controller::curr()->getRequest(),
            $result
        );
        $this->assertNull($member);
        $this->assertFalse($result->isValid());
        $member = new Member();
        $member->Email = $email;
        $this->assertTrue($member->isLockedOut());
        $this->assertFalse($member->canLogIn());
    }
}