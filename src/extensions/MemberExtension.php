<?php

namespace ilateral\SilverStripe\AuthUsername\Extensions;

use SilverStripe\Core\Convert;
use SilverStripe\ORM\DataObject;
use SilverStripe\Forms\FieldList;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\ORM\ValidationException;

/**
 * Add additional variables to Member
 *
 * @author morven
 */
class MemberExtension extends DataExtension
{
    private static $db = [
        "Username" => "Varchar"
    ];
    
    private static $indexes = [
        "Username" => true
    ];

    private static $summary_fields = array(
        'FirstName',
        'Surname',
        'Username',
        'Email',
    );

    /**
     * Update username field on a member
     * 
     * @param FieldList $fields List of fields from CMS
     * 
     * @return null
     */
    public function updateCMSFields(FieldList $fields) 
    {
        $username_field = $fields->dataFieldByName("Username");

        if ($username_field) {
            $username_field
                ->setTitle(_t('AuthUsernameOrEmail.Title', "Username"))
                ->setDescription(_t("AuthUsernameOrEmail.Description", "This is used for logging in"));
            $fields->insertBefore(
                $username_field,
                "FirstName"
            );
        }
    }
}
