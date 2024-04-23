# JSRunner 2

![Build and Test](https://github.com/dannyswat/jsrunner2/actions/workflows/go.yml/badge.svg)

A simple web app to run javascript locally with online script storage. You can create your own account and save your own javascripts for your work. Passwords are securely hashed with Argon2id but no other security measures have been implemented. Please do not rely on it. :)

## Usage

- Generate code or scripts from lines of input
- Simple utilities

## Change log

23 Apr 2024 
- Rewrite with Go (for fun) as JSRunner 2 (Previous version: https://github.com/dannyswat/jsrunner)
- Allow public access without login
- Allow self registration
- Abandone Basic Authentication (because my company blocks basic authentication)
- Still using jQuery because I am lazy to change
