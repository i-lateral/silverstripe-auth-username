<?php

// Add new authenticator
Authenticator::register_authenticator('UsernameOrEmailAuthenticator');

// Remove default email authenticator
Authenticator::unregister("MemberAuthenticator");