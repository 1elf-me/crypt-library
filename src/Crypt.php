<?php
namespace CryptLibrary;

use Exception;
use RuntimeException;

class Crypt
{
    private static $method = 'aes-256-cbc';

    /**
     * Encrypt data with given key
     * @param $data
     * @param $key
     * @return string
     * @throws RuntimeException
     */
    public static function encrypt($data, $key): string
    {
        // Remove the base64 encoding from our key
        $encryption_key = base64_decode($key);

        // Generate an initialization vector
        if (($ocivl = openssl_cipher_iv_length(self::$method)) === false || ($iv = openssl_random_pseudo_bytes($ocivl)) === false) {
            throw new RuntimeException('Encryption initialization error!');
        }

        // Encrypt the data using AES 256 encryption in CBC mode using our encryption key and initialization vector.
        if (($encrypted = openssl_encrypt($data, self::$method, $encryption_key, 0, $iv)) === false) {
            throw new RuntimeException('Encryption error!');
        }

        // The $iv is just as important as the key for decrypting, so save it with our encrypted data using a unique separator (::)
        return $encrypted . '::' . $iv;
    }

    /**
     * Decrypt data with given key
     * @param $data
     * @param $key
     * @return string
     * @throws RuntimeException
     */
    public static function decrypt($data, $key): string
    {
        // Remove the base64 encoding from our key
        $encryption_key = base64_decode($key);

        // To decrypt, split the encrypted data from our IV - our unique separator used was "::"
        list($encrypted_data, $iv) = explode('::', $data, 2);

        // Encrypt the data
        if(($decryptedData = openssl_decrypt($encrypted_data, self::$method, $encryption_key, 0, $iv)) === false) {
            throw new RuntimeException('Decryption error!');
        }

        return $decryptedData;
    }

    /**
     * Generate key file
     * @param $filename
     * @param $password
     * @return bool
     * @throws RuntimeException|Exception
     */
    public static function generateKeyFile($filename, $password): bool
    {
        $contentEncryptionKey = random_bytes(512);
        $encryptedContentEncryptionKey = self::encrypt($contentEncryptionKey, $password);

        if ((file_put_contents($filename, $encryptedContentEncryptionKey)) === false) {
            throw new RuntimeException('Cannot save user key to file!');
        }

        return true;
    }

    /**
     * @param $password
     * @return string
     * @throws Exception
     */
    public static function generateContentEncryptionKey($password): string
    {
        $contentEncryptionKey = random_bytes(512);
        return self::encrypt($contentEncryptionKey, $password);
    }
}
