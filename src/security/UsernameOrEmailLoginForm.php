<?php

namespace ilateral\SilverStripe\AuthUsername\Security;

use SilverStripe\Forms\TextField;
use SilverStripe\Security\Security;
use SilverStripe\Security\MemberAuthenticator\MemberLoginForm;
use ilateral\SilverStripe\AuthUsername\Security\UsernameOrEmailAuthenticator;

/**
 * Custom login form that swaps email field for ident
 */
class UsernameOrEmailLoginForm extends MemberLoginForm
{

    protected $authenticator_class = UsernameOrEmailAuthenticator::class;

    /**
     * Overwrite default fields to swap email for identity
     * 
     * @return FieldList
     */
    protected function getFormFields()
    {
        $fields = parent::getFormFields();

        $identity_field = TextField::create(
            UsernameOrEmailAuthenticator::IDENTITY,
            _t('AuthUsernameOrEmail.UsernameOrEmail', 'Username or Email')
        );

        if (!Security::config()->remember_username) {
            // Some browsers won't respect this attribute unless it's added to the form
            $this->setAttribute('autocomplete', 'off');
            $identity_field->setAttribute('autocomplete', 'off');
        }

        $fields->replaceField("Email", $identity_field);

        return $fields;
    }
}
