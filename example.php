<?php

use CryptLibrary\Crypt;
use CryptLibrary\UserCrypt;

require_once __DIR__ . '/vendor/autoload.php';

$userKeyFilename = 'example/member.key';
$userKeyPassword = 'Secret!'; // In prod. only stored temporary

// Obtaining a new user key file (must be saved for later)
$crypt = new Crypt();
$crypt->generateKeyFile($userKeyFilename, $userKeyPassword);

// En- & Decrypt user generated content
$userCrypt = new UserCrypt($userKeyFilename, $userKeyPassword);
$encryptedData = $userCrypt->encryptFile('example/test.png');
$decryptedData = $userCrypt->decrypt($encryptedData);

// Return user generated content
header("Content-Type: image/png");
header("Content-Length: " . strlen($decryptedData));

echo $decryptedData;