<?php
/**
 * Add additional variables to Member
 *
 * @author morven
 */
class UsernameMemberExtension extends DataExtension {
    public static $db = array(
        "Username" => "Varchar"
    );
    
    public static $indexes = array(
		"Username" => array('type'=>'unique', 'value'=>'Username')
	);
	
	public function onBeforeWrite() {
		if($username = $this->owner->Username) {
			$identifierField = 'Username';
			$id = $this->owner->ID;

			$idClause = ($id) ? sprintf(" AND \"Member\".\"ID\" <> %d", (int)$id) : '';
			$existingRecord = DataObject::get_one(
				'Member', 
				sprintf(
					"\"%s\" = '%s' %s",
					$identifierField,
					Convert::raw2sql($username),
					$idClause
				)
			);

			if($existingRecord) {
				throw new ValidationException(new ValidationResult(false, _t(
					'Member.ValidationIdentifierFailed', 
					'Can\'t overwrite existing member #{id} with identical identifier ({name} = {value})', 
					'Values in brackets show "fieldname = value", usually denoting an existing username',
					array(
						'id' => $existingRecord->ID,
						'name' => $identifierField,
						'value' => $username
					)
				)));
			}
		}

		parent::onBeforeWrite();
	}

	public function updateCMSFields(FieldList $fields) {
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
