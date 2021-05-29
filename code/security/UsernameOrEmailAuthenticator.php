<?php

/**
 * Overwrite MemberAuthenticator and add support for a usernajme as well as
 * an email address for authentication
 *
 */
class UsernameOrEmailAuthenticator extends MemberAuthenticator
{
    /**
	 * Overwrite standard authentication in order to also look for user ID
     * (as well as email)
	 *
	 * @param array $data
	 * @param Form $form
	 * @param bool &$success Success flag
	 * @return Member Found member, regardless of successful login
	 */
	protected static function authenticate_member($data, $form, &$success)
    {
		// Default variables
		$success = false;
		$member = null;
		$identity = null;
        $isLockedOut = false;
        $result = null;
        $filter = null;

        // Attempt to identify by temporary ID
		if(!empty($data['tempid'])) {
			// Find user by tempid, in case they are re-validating an existing session
			$member = Member::member_from_tempid($data['tempid']);
			if ($member) {
                $identity = $member->Email;
            }
		}

		// Otherwise, get identifier from posted value instead
		if(!$member && !empty($data['Email'])) {
			$identity = $data['Email'];
		}

		// Check default login (see Security::setDefaultAdmin())
		$id_default_admin = $identity === Security::default_admin_username();
		if($id_default_admin) {
			// If logging is as default admin, ensure record is setup correctly
			$member = Member::default_admin();
			$success = !$member->isLockedOut() && Security::check_default_admin($identity, $data['Password']);
			//protect against failed login
			if ($success) {
				return $member;
			}
		}

        // Now check if identity is an email address or username and setup filters
        if ($identity && filter_var($identity, FILTER_VALIDATE_EMAIL)) {
            $filter = array('Email' => $identity);
        } else {
            $filter = array('Username' => $identity);
        }

		// Attempt to identify user
		if(!$member && $filter) {
			// Find user by filter (Username or Email)
			$member = Member::get()
				->filter($filter)
				->first();
		}

		// Validate against member if possible
		if($member && !$id_default_admin) {
			$result = $member->checkPassword($data['Password']);
			$success = $result->valid();
		} else {
			$result = new ValidationResult(false, _t('Member.ERRORWRONGCRED'));
		}

		// Emit failure to member and form (if available)
		if(!$success) {
			if($member) $member->registerFailedLogin();
			if($form) $form->sessionMessage($result->message(), 'bad');
		} else {
			if($member) $member->registerSuccessfulLogin();
		}

		return $member;
	}

    /**
     * Tell this Authenticator to use your custom login form
     * The 3rd parameter MUST be 'LoginForm' to fit within the authentication
     * framework
     *
     * @param $controller the controller to add this form to
     * @return UsernameOrEmailLoginForm
     */
    public static function get_login_form(Controller $controller) {
        return UsernameOrEmailLoginForm::create($controller, "LoginForm");
    }

    /**
     * Give a title to the Authenticator tab (when multiple Authenticators are
     * registered)
     *
     * @return String
     */
    public static function get_name() {
        return _t("AuthUsernameOrEmail.Title", "Username or Email and Password");
    }

}
