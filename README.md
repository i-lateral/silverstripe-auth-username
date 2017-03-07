# Silverstripe Auth Username Module

![Travis Support](https://travis-ci.org/i-lateral/silverstripe-auth-username.svg?branch=master)

Adds ability to log users into a Silverstripe installation via either a username
Username OR Email address.

Also provides a custom widget that adds a Username or Email login form to the
sidebar.

## Maintainer Contact

 * Mo <morven@ilateral.co.uk>

## Requirements

 * Silverstripe Framework 3.1.x

## Installation

The preffered method of installation is Composer (see the
[official docs](https://docs.silverstripe.org/en/3/developer_guides/extending/modules/#installation))

To install via composer run the following:

    composer require i-lateral/silverstripe-auth-username:1.*

NOTE: The above will install the latest version of 1.*

## Usage

Once installed, make sure you run a dev/build to add the Username field to
a Member.

Now when you go to login you will get a Username or Email form (insted of the
default email form).