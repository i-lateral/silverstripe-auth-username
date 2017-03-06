<?php

class UsernameOrEmailLoginForm extends MemberLoginForm {

    protected $authenticator_class = 'UsernameOrEmailAuthenticator';

    public function __construct($controller, $name, $fields = null, $actions = null, $checkCurrentUser = true) {

        $form_action_url = Controller::join_links(
            BASE_URL,
            "Security",
            $name
        );

        $lost_password_url = Controller::join_links(
            BASE_URL,
            "Security",
            "lostpassword"
        );

        if(isset($_REQUEST['BackURL']))
            $backURL = $_REQUEST['BackURL'];
        else
            $backURL = Session::get('BackURL');

        $fields = new FieldList(
            HiddenField::create("AuthenticationMethod", null, $this->authenticator_class, $this),
            TextField::create('Identity', _t('AuthUsernameOrEmail.UsernameOrEmail', 'Username or Email')),
            PasswordField::create("Password", _t('Member.PASSWORD', 'Password'))
        );

        if(Security::config()->autologin_enabled) {
            $fields->push(new CheckboxField(
                "Remember",
                _t('Member.REMEMBERME', "Remember me?")
            ));
        }

        $actions = new FieldList(
            FormAction::create('dologin', 'Login'),
            LiteralField::create(
                'forgotPassword',
                '<p id="ForgotPassword"><a href="' . $lost_password_url . '">'
                . _t('Member.BUTTONLOSTPASSWORD', "I've lost my password") . '</a></p>'
            )
        );

        // LoginForm does its magic
        parent::__construct($controller, $name, $fields, $actions);

        $this
            ->setAttribute("action",$form_action_url);
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
