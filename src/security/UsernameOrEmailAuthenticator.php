<?php

namespace ilateral\SilverStripe\AuthUsername\Security;

use InvalidArgumentException;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\LoginAttempt;
use SilverStripe\Security\DefaultAdminService;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use ilateral\SilverStripe\AuthUsername\Security\UsernameOrEmailLoginForm;
use ilateral\SilverStripe\AuthUsername\Security\UsernameOrEmailLoginHandler;


/**
 * Overwrite MemberAuthenticator and add support for a usernajme as well as
 * an email address for authentication
 */
class UsernameOrEmailAuthenticator extends MemberAuthenticator
{
    const IDENTITY = "Identity";

    /**
     * Overwrite standard authentication in order to also look for user ID
     * (as well as email)
     *
     * @param array       $data
     * @param HTTPRequest $request
     * @param Member      $member
     * @param boolean     $success
     *
     * @return Member Found member, regardless of successful login
     */
    protected function authenticateMember($data, ValidationResult &$result = null, Member $member = null)
    {
        $ident = !empty($data[self::IDENTITY]) ? $data[self::IDENTITY] : null;
        $result = $result ?: ValidationResult::create();
        $field = Member::config()->get('unique_identifier_field');

        // Check default login (see Security::setDefaultAdmin())
        $asDefaultAdmin = DefaultAdminService::isDefaultAdmin($ident);

        if ($asDefaultAdmin) {
            // If logging is as default admin, ensure record is setup correctly
            $member = DefaultAdminService::singleton()->findOrCreateDefaultAdmin();
            $member->validateCanLogin($result);
            if ($result->isValid()) {
                // Check if default admin credentials are correct
                if (DefaultAdminService::isDefaultAdminCredentials($ident, $data['Password'])) {
                    return $member;
                } else {
                    $result->addError(
                        _t(
                            'SilverStripe\\Security\\Member.ERRORWRONGCRED',
                            "The provided details don't seem to be correct. Please try again."
                        )
                    );
                }
            }
        }

        // Attempt to identify user by email
        if (!$member && $ident) {
            // Now check if identity is an email address or username
            // and setup filters
            if ($ident && !filter_var($ident, FILTER_VALIDATE_EMAIL)) {
                $field = Member::config()->get('alt_identifier_field');
            }
            $member = Member::get()
                ->filter($field, $ident)
                ->first();
            
            /*var_dump($field);
            var_dump($ident);
            var_dump($member);
            exit;*/
        }

        // Validate against member if possible
        if ($member && !$asDefaultAdmin) {
            $this->checkPassword($member, $data['Password'], $result);
        } elseif (!$asDefaultAdmin) {
            // spoof a login attempt
            $tempMember = Member::create();
            $tempMember->{$field} = $ident;
            $tempMember->validateCanLogin($result);
        }

        // Emit failure to member and form (if available)
        if (!$result->isValid()) {
            if ($member) {
                $member->registerFailedLogin();
            }
        } elseif ($member) {
            $member->registerSuccessfulLogin();
        } else {
            // A non-existing member occurred. This will make the result "valid" so let's invalidate
            $result->addError(
                _t(
                    'SilverStripe\\Security\\Member.ERRORWRONGCRED',
                    "The provided details don't seem to be correct. Please try again."
                )
            );
            return null;
        }

        return $member;
    }

    /**
     * Log login attempt, again largly copied from MemberAuthenticator
     *
     * @param array       $data
     * @param HTTPRequest $request
     * @param Member      $member
     * @param boolean     $success
     */
    protected function recordLoginAttempt($data, HTTPRequest $request, $member, $success)
    {
        if (!Security::config()->get('login_recording')
            && !Member::config()->get('lock_out_after_incorrect_logins')
        ) {
            return;
        }

        // Check email is valid
        /**
 * @skipUpgrade 
*/
        $ident = isset($data['Ident']) ? $data['Ident'] : null;
        if (is_array($ident)) {
            throw new InvalidArgumentException("Bad email passed to MemberAuthenticator::authenticate(): $email");
        }

        $attempt = LoginAttempt::create();
        if ($success && $member) {
            // successful login (member is existing with matching password)
            $attempt->MemberID = $member->ID;
            $attempt->Status = LoginAttempt::SUCCESS;

            // Audit logging hook
            $member->extend('authenticationSucceeded');
        } else {
            // Failed login - we're trying to see if a user exists with this email (disregarding wrong passwords)
            $attempt->Status = LoginAttempt::FAILURE;
            if ($member) {
                // Audit logging hook
                $attempt->MemberID = $member->ID;
                $member->extend('authenticationFailed', $data, $request);
            } else {
                // Audit logging hook
                Member::singleton()
                   ->extend('authenticationFailedUnknownUser', $data, $request);
            }
        }

        if ($member && $member->Email) {
            $email = $member->Email;
        } else {
            $email = $ident;
        }

        $attempt->Email = $email;
        $attempt->IP = $request->getIP();
        $attempt->write();
    }

    /**
     * @param string $link
     * @return LoginHandler
     */
    public function getLoginHandler($link)
    {
        return UsernameOrEmailLoginHandler::create($link, $this);
    }

    /**
     * Give a title to the Authenticator tab (when multiple Authenticators are
     * registered)
     *
     * @return string
     */
    public static function get_name() 
    {
        return _t("AuthUsernameOrEmail.Title", "Username or Email and Password");
    }

}
