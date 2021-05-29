<?php

class UsernameOrEmailLoginForm extends MemberLoginForm
{

    protected $authenticator_class = 'UsernameOrEmailAuthenticator';

    public function __construct($controller, $name, $fields = null, $actions = null, $checkCurrentUser = true)
    {
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

        if (isset($_REQUEST['BackURL'])) {
            $backURL = $_REQUEST['BackURL'];
        } else {
            $backURL = Session::get('BackURL');
        }

        $fields = new FieldList(
            HiddenField::create(
                "AuthenticationMethod",
                null,
                $this->authenticator_class,
                $this
            ),
            $identity_field = TextField::create(
                'Identity',
                _t('AuthUsernameOrEmail.UsernameOrEmail', 'Username or Email')
            ),
            PasswordField::create(
                "Password",
                _t('Member.PASSWORD', 'Password')
            )
        );

        if(!Security::config()->remember_username) {
            // Some browsers won't respect this attribute unless it's added to the form
            $this->setAttribute('autocomplete', 'off');
            $identity_field->setAttribute('autocomplete', 'off');
        }

        if(Security::config()->autologin_enabled) {
            $fields->push(new CheckboxField(
                "Remember",
                _t('Member.REMEMBERME', "Remember me?")
            ));
        }


		if (isset($backURL)) {
			$fields->push(new HiddenField('BackURL', 'BackURL', $backURL));
		}

        $actions = new FieldList(
            FormAction::create('dologin', _t('Member.BUTTONLOGIN', "Log in")),
            LiteralField::create(
                'forgotPassword',
                '<p id="ForgotPassword"><a href="' . $lost_password_url . '">'
                . _t('Member.BUTTONLOSTPASSWORD', "I've lost my password") . '</a></p>'
            )
        );

		// Reduce attack surface by enforcing POST requests
		$this->setFormMethod('POST', true);

        // LoginForm does its magic
        parent::__construct($controller, $name, $fields, $actions);

        // Focus on the identity input when the page is loaded
        $js = <<<JS
            (function() {
                var el = document.getElementById("UsernameOrEmailLoginForm_LoginForm_Identity");
                if(el && el.focus && (typeof jQuery == 'undefined' || jQuery(el).is(':visible'))) el.focus();
            })();
JS;
        Requirements::customScript($js, 'UsernameOrEmailLoginFormFieldFocus');

        $this
            ->setAttribute("action",$form_action_url);
			
        $this
            ->setValidator(RequiredFields::create('Identity', 'Password'));

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
