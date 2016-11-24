<?php
class UsernameOrEmailAuthenticator extends Authenticator {

    /**
     * @var Array Contains encryption algorithm identifiers.
     *  If set, will migrate to new precision-safe password hashing
     *  upon login. See http://open.silverstripe.org/ticket/3004.
     */
    public static $migrate_legacy_hashes = array(
        'md5' => 'md5_v2.4',
        'sha1' => 'sha1_v2.4'
    );

    /**
     * Method to authenticate a user, shamlessly copied and tweaked from
     * MemberAuthenticator
     *
     */
    public static function authenticate($RAW_data, Form $form = null) {
        if(array_key_exists('Identity', $RAW_data) && $RAW_data['Identity']){
            $SQL_user = Convert::raw2sql($RAW_data['Identity']);
        } else {
            return false;
        }

        $isLockedOut = false;
        $result = null;

        // See if identity is an email address, otherwise, check username
        if(filter_var($RAW_data['Identity'], FILTER_VALIDATE_EMAIL))
            $filter = array('Email' => $RAW_data['Identity']);
        else
            $filter = array('Username' => $RAW_data['Identity']);

        // Default login (see Security::setDefaultAdmin())
        if(Security::check_default_admin($RAW_data['Identity'], $RAW_data['Password'])) {
            $member = Security::findAnAdministrator();
        } else {
            $member = Member::get()->filter($filter)->first();

            if($member) {
                $result = $member->checkPassword($RAW_data['Password']);
            } else {
                $result = new ValidationResult(false, _t('Member.ERRORWRONGCRED'));
            }

            if($member && !$result->valid()) {
                $member->registerFailedLogin();
                $member = false;
            }
        }

        // Optionally record every login attempt as a {@link LoginAttempt} object
        /**
         * TODO We could handle this with an extension
         */
        if(Security::login_recording()) {
            $attempt = new LoginAttempt();
            if($member) {
                // successful login (member is existing with matching password)
                $attempt->MemberID = $member->ID;
                $attempt->Status = 'Success';

                // Audit logging hook
                $member->extend('authenticated');
            } else {
                // failed login - we're trying to see if a user exists with this email (disregarding wrong passwords)
                $existingMember = DataObject::get_one(
                    "Member",
                    "\"" . Member::get_unique_identifier_field() . "\" = '$SQL_user'"
                );
                if($existingMember) {
                    $attempt->MemberID = $existingMember->ID;

                    // Audit logging hook
                    $existingMember->extend('authenticationFailed');
                } else {

                    // Audit logging hook
                    singleton('Member')->extend('authenticationFailedUnknownUser', $RAW_data);
                }
                $attempt->Status = 'Failure';
            }
            if(is_array($RAW_data['Email'])) {
                user_error("Bad email passed to MemberAuthenticator::authenticate(): $RAW_data[Email]", E_USER_WARNING);
                return false;
            }

            $attempt->Email = $RAW_data['Email'];
            $attempt->IP = Controller::curr()->getRequest()->getIP();
            $attempt->write();
        }

        // Legacy migration to precision-safe password hashes.
        // A login-event with cleartext passwords is the only time
        // when we can rehash passwords to a different hashing algorithm,
        // bulk-migration doesn't work due to the nature of hashing.
        // See PasswordEncryptor_LegacyPHPHash class.
        if(
            $member // only migrate after successful login
            && self::$migrate_legacy_hashes
            && array_key_exists($member->PasswordEncryption, self::$migrate_legacy_hashes)
        ) {
            $member->Password = $RAW_data['Password'];
            $member->PasswordEncryption = self::$migrate_legacy_hashes[$member->PasswordEncryption];
            $member->write();
        }

        if($member) {
            Session::clear('BackURL');
        } else {
            if($form && $result) $form->sessionMessage(_t('Member.ERRORWRONGCRED'), 'bad');
        }

        return $member;
    }

    // Tell this Authenticator to use your custom login form
    // The 3rd parameter MUST be 'LoginForm' to fit within the authentication framework
    public static function get_login_form(Controller $controller) {
        return UsernameOrEmailLoginForm::create($controller, "LoginForm");
    }

    // give a title to the Authenticator tab (when multiple Authenticators are registered)
    public static function get_name() {
        return "Username or Email and Password";
    }

}
