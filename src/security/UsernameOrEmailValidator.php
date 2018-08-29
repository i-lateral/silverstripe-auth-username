<?php

namespace ilateral\SilverStripe\AuthUsername\Security;

use SilverStripe\Security\Member;
use SilverStripe\Security\Member_Validator;
use SilverStripe\Forms\GridField\GridFieldDetailForm_ItemRequest;


class UsernameOrEmailValidator extends Member_Validator
{
    /**
     * Check if the submitted member data is valid (server-side)
     *
     * Check if a member with that email doesn't already exist, or if it does
     * that it is this member.
     *
     * @param array $data Submitted data
     * @return bool Returns TRUE if the submitted data is valid, otherwise
     *              FALSE.
     */
    public function php($data)
    {
        $valid = parent::php($data);
        $ident = (string)Member::config()->alt_identifier_field;

        // If the primary ident was valid, check the alt
        if ($valid) {

            // Only validate identifier field if it's actually set.
            $id = isset($data['ID']) ? (int)$data['ID'] : 0;
            if (isset($data[$ident])) {
                if (!$id && ($ctrl = $this->form->getController())) {
                    // get the record when within GridField (Member editing page in CMS)
                    if ($ctrl instanceof GridFieldDetailForm_ItemRequest && $record = $ctrl->getRecord()) {
                        $id = $record->ID;
                    }
                }

                // If there's no ID passed via controller or form-data, use the assigned member (if available)
                if (!$id && ($member = $this->getForMember())) {
                    $id = $member->exists() ? $member->ID : 0;
                }

                // set the found ID to the data array, so that extensions can also use it
                $data['ID'] = $id;

                $members = Member::get()->filter($ident, $data[$ident]);
                if ($id) {
                    $members = $members->exclude('ID', $id);
                }

                if ($members->count() > 0) {
                    $this->validationError(
                        $ident,
                        _t(
                            'SilverStripe\\Security\\Member.VALIDATIONMEMBEREXISTS',
                            'A member already exists with the same {identifier}',
                            ['identifier' => Member::singleton()->fieldLabel($ident)]
                        ),
                        'required'
                    );
                    $valid = false;
                }
            }
        }
        return $valid;
    }
}