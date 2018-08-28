<?php

/*
 * Login widget for displaying a login box. Once logged in the form is hidden
 *
 */
if(class_exists("Widget")) {

class UsernameOrEmailLoginWidget extends Widget {

    static $title = "Login";
    static $cmsTitle = "Login with Username or Email";
    static $description = "Allows a user to log in using their Username OR Email. It is hidden if a user is logged in";
    protected static $BadLoginURL = false;

    function LoggedIn() {
        return Member::currentUser();
    }

    function Title() {
        return ($this->LoggedIn()) ? _t('LoginWidget.LOGGEDIN','Logged In') : _t('LoginWidget.LOGIN','Login');
    }

    function LoginForm() {
        if (self::$BadLoginURL) {
            $page = self::$BadLoginURL;
        } else {
            $page = Director::get_current_page()->URLSegment;
        }
        Session::set("BadLoginURL", Director::absoluteURL($page, true));

        $controller = new UsernameOrEmailLoginWidget_Controller($this);
        $form = $controller->LoginForm();
        $this->extend('updateLoginForm', $form);
        return $form;
    }

    public static function setBadLoginURL($url) {
        self::$BadLoginURL = $url;
    }

}

class UsernameOrEmailLoginWidget_Controller extends Widget_Controller {

    function LoginForm() {
        $form = new UsernameOrEmailLoginForm($this, 'LoginForm');
        return $form;
    }

    function Link($action = null) {
        return $this->class;
    }

}

}
