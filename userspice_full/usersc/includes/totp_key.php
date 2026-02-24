<?php
/**
 * TOTP Encryption Configuration
 *
 * SECURITY WARNING: DO NOT COMMIT THIS FILE.
 * Recommended permissions: 0400
 *
 * PREFERRED APPROACH: Store these values in your .env file instead:
 * TOTP_ENC_KEY=XXXXXXXXXXXXXXXXXXXXXXXX
 * TOTP_CRYPTO_ENGINE=sodium
 *
 * This file is designed to be used when an env file is not possible.
 * If you have an env file, you should delete this file and load your
 * constants from your .env file instead.
 * We've automatically added this file to your .gitignore (if one exists).
 *
 * --------------------------------------------------------------------
 * EXAMPLE: Loading constants from a .env file
 * --------------------------------------------------------------------
 * If you are using a library like 'vlucas/phpdotenv', you can load
 * the constants in your application's bootstrap file like this:
 *
 * require_once '/path/to/vendor/autoload.php';
 * $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
 * $dotenv->load();
 *
 * // Define constants from environment variables
 * define('TOTP_ENC_KEY', $_ENV['TOTP_ENC_KEY']);
 * define('TOTP_CRYPTO_ENGINE', $_ENV['TOTP_CRYPTO_ENGINE']);
 * 
 * // Then delete the constants from this file
 * --------------------------------------------------------------------
 *
 * Generated: 2025-06-22T03:39:31-04:00
 */
const TOTP_ENC_KEY = 'U/0YWVP4U6I6c3sih1naD7SDOIdi2S6vJbbXh308l8c=';
const TOTP_CRYPTO_ENGINE = 'sodium';

// To migrate servers, you may define TOTP_FORCE_CRYPTO_ENGINE
// const TOTP_FORCE_CRYPTO_ENGINE = 'sodium'; // or 'openssl'