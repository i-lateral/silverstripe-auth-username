<?php

class UsernameOrEmailLoginForm extends MemberLoginForm {

    protected $authenticator_class = 'UsernameOrEmailAuthenticator';

    public function __construct($controller, $name, $fields = null, $actions = null, $checkCurrentUser = true) {
        if(isset($_REQUEST['BackURL']))
            $backURL = $_REQUEST['BackURL'];
        else
            $backURL = Session::get('BackURL');

        $fields = new FieldList(
            HiddenField::create("AuthenticationMethod", null, $this->authenticator_class, $this),
            TextField::create('Identity', _t('Member.IDENTITY', 'Username or Email')),
            PasswordField::create("Password", _t('Member.PASSWORD', 'Password'))
        );

        if(Security::config()->autologin_enabled) {
            $fields->push(new CheckboxField(
                "Remember",
                _t('Member.REMEMBERME', "Remember me?")
            ));
        }

        // LoginForm does its magic
        parent::__construct($controller, $name, $fields, $actions);

        // Focus on the email input when the page is loaded
        $js = <<<JS
            (function() {
                var el = document.getElementById("UsernameOrEmailLoginForm_LoginForm_Identity");
                if(el && el.focus && (typeof jQuery == 'undefined' || jQuery(el).is(':visible'))) el.focus();
            })();
JS;
        Requirements::customScript($js);
    }

    //call our own Authenticator
    public function performLogin($data) {
        if($member = UsernameOrEmailAuthenticator::authenticate($data, $this)) {
            $member->LogIn(isset($data['Remember']));
            return $member;
        } else {
           return false;
        }
    }
}
