<?php

namespace ilateral\SilverStripe\AuthUsername\Security;

use SilverStripe\Security\MemberAuthenticator\LoginHandler;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use ilateral\SilverStripe\AuthUsername\Security\UsernameOrEmailLoginForm;

/**
 * Custom login handler that returns our custom loginform
 */
class UsernameOrEmailLoginHandler extends LoginHandler
{
    /**
     * @var array
     * @config
     */
    private static $allowed_actions = [
        'login',
        'LoginForm',
        'logout',
    ];

    /**
     * Return the UsernameOrEmailLoginForm form
     *
     * @skipUpgrade
     * @return MemberLoginForm
     */
    public function loginForm()
    {
        return UsernameOrEmailLoginForm::create(
            $this,
            get_class($this->authenticator),
            'LoginForm'
        );
    }
}