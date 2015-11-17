<?php

// Add new authenticator
Authenticator::register_authenticator('UsernameOrEmailAuthenticator');

Authenticator::set_default_authenticator("UsernameOrEmailAuthenticator"); // makes username authentication default
Authenticator::unregister("MemberAuthenticator"); // removes default email + password authentication
