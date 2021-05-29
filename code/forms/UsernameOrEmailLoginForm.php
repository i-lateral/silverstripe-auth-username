<?php

class UsernameOrEmailLoginForm extends MemberLoginForm
{

    protected $authenticator_class = 'UsernameOrEmailAuthenticator';

    public function __construct($controller, $name, $fields = null, $actions = null, $checkCurrentUser = true)
    {
        parent::__construct($controller, $name, $fields, $actions);

        if ($emailField = $this->Fields()->fieldByName("Email")) {
            $emailField->setTitle(_t('AuthUsernameOrEmail.UsernameOrEmail', 'Username or Email'));
        }

        // Focus on the Email input when the page is loaded
        $js = <<<JS
            (function() {
                var el = document.getElementById("UsernameOrEmailLoginForm_LoginForm_Email");
                if(el && el.focus && (typeof jQuery == 'undefined' || jQuery(el).is(':visible'))) el.focus();
            })();
JS;
        Requirements::customScript($js, 'UsernameOrEmailLoginFormFieldFocus');
    }

    /**
     * Attempt login via our own Authenticator
     *
     * @return Member
     */
    public function performLogin($data)
    {
        $member = null;

        try {
            $member = call_user_func_array(array(
                $this->authenticator_class, 'authenticate'),
                array($data, $this)
            );

            if($member) {
                $member->LogIn(isset($data['Remember']));
                return $member;
            } else {
                $this->extend('authenticationFailed', $data);
            }
        } catch (ValidationException $e) {
            error_log($e->getMessage());
        } catch (Exception $e) {
            error_log($e->getMessage());
        }

        $this->sessionMessage(_t('AuthUsernameOrEmail.LoginError', 'There was an error logging in'), "bad");

        return $member;
    }
}
