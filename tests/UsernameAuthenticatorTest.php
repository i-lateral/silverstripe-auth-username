<?php
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

	public function setUp()
    {
		parent::setUp();

		$this->defaultUsername = Security::default_admin_username();
		$this->defaultPassword = Security::default_admin_password();
		Security::clear_default_admin();
		Security::setDefaultAdmin('admin', 'password');
	}

	public function tearDown()
    {
		Security::setDefaultAdmin($this->defaultUsername, $this->defaultPassword);
		parent::tearDown();
	}

	public function testGenerateLoginForm()
    {
		$controller = new Security();

		// Create basic login form
		$frontendForm = UsernameOrEmailAuthenticator::get_login_form($controller);
		$this->assertTrue($frontendForm instanceof MemberLoginForm);
	}

	/**
	 * Test that a member can be authenticated via their temp id
	 */
	public function testAuthenticateByTempID()
    {
		$member = new Member();
		$member->Email = 'test1@test.com';
		$member->PasswordEncryption = "sha1";
		$member->Password = "mypassword";
		$member->write();

		// Make form
		$controller = new Security();
		$form = new Form($controller, 'Form', new FieldList(), new FieldList());

		// If the user has never logged in, then the tempid should be empty
		$tempID = $member->TempIDHash;
		$this->assertEmpty($tempID);

		// If the user logs in then they have a temp id
		$member->logIn(true);
		$tempID = $member->TempIDHash;
		$this->assertNotEmpty($tempID);

		// Test correct login
		$result = UsernameOrEmailAuthenticator::authenticate(array(
			'tempid' => $tempID,
			'Password' => 'mypassword'
		), $form);
		$this->assertNotEmpty($result);
		$this->assertEquals($result->ID, $member->ID);
		$this->assertEmpty($form->Message());

		// Test incorrect login
		$form->clearMessage();
		$result = UsernameOrEmailAuthenticator::authenticate(array(
			'tempid' => $tempID,
			'Password' => 'notmypassword'
		), $form);
		$this->assertEmpty($result);
		$this->assertEquals('The provided details don&#039;t seem to be correct. Please try again.', $form->Message());
		$this->assertEquals('bad', $form->MessageType());
	}

	/**
	 * Test that the default admin can be authenticated
	 */
	public function testDefaultAdmin()
    {
		// Make form
		$controller = new Security();
		$form = new Form($controller, 'Form', new FieldList(), new FieldList());

		// Test correct login
		$result = UsernameOrEmailAuthenticator::authenticate(array(
			'Email' => 'admin',
			'Password' => 'password'
		), $form);
		$this->assertNotEmpty($result);
		$this->assertEquals($result->Email, Security::default_admin_username());
		$this->assertEmpty($form->Message());

		// Test incorrect login
		$form->clearMessage();
		$result = UsernameOrEmailAuthenticator::authenticate(array(
			'Email' => 'admin',
			'Password' => 'notmypassword'
		), $form);
		$this->assertEmpty($result);
		$this->assertEquals('The provided details don&#039;t seem to be correct. Please try again.', $form->Message());
		$this->assertEquals('bad', $form->MessageType());
	}

	public function testDefaultAdminLockOut()
	{
		Config::inst()->update('Member', 'lock_out_after_incorrect_logins', 1);
		Config::inst()->update('Member', 'lock_out_delay_mins', 10);
		SS_Datetime::set_mock_now('2016-04-18 00:00:00');
		$controller = new Security();
		$form = new Form($controller, 'Form', new FieldList(), new FieldList());

		// Test correct login
		UsernameOrEmailAuthenticator::authenticate(array(
			'Email' => 'admin',
			'Password' => 'wrongpassword'
		), $form);

		$this->assertTrue(Member::default_admin()->isLockedOut());
		$this->assertEquals(Member::default_admin()->LockedOutUntil, '2016-04-18 00:10:00');
	}
}
