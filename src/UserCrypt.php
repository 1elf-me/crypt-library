<?php

namespace CryptLibrary;

use RuntimeException;

/**
 * Class UserCrypt
 * @package CryptLibrary
 */
class UserCrypt
{
    private $userKey;
    private $userKeyPassword;

    /**
     * User constructor
     * @param $userKey string Filename or string of user key file
     * @param $userKeyPassword string Password for user key file
     */
    public function __construct(string $userKey, string $userKeyPassword)
    {
        $this->userKey = @is_file($userKey) ? file_get_contents($userKey) : $userKey;
        $this->userKeyPassword = $userKeyPassword;
    }

    /**
     * Content encryption by file
     * @param string $filename
     * @param null $encryptedFilename
     * @return string
     * @throws RuntimeException
     */
    public function encryptFile(string $filename, $encryptedFilename = null): string
    {
        $encryptedData = $this->encrypt(file_get_contents($filename));

        if ($encryptedFilename && !file_put_contents($encryptedFilename, $encryptedData)) {
            throw new RuntimeException('Cannot save encrypted data to file!');
        }

        return $encryptedData;
    }

    /**
     * Content encryption
     * @param $data string Content of encrypted file
     * @return string
     */
    public function encrypt(string $data): string
    {
        return Crypt::encrypt($data, $this->getContentEncryptionKey());
    }

    /**
     * Get content encryption key
     * @return string
     */
    private function getContentEncryptionKey(): string
    {
        return Crypt::decrypt($this->userKey, $this->userKeyPassword);
    }

    /**
     * Content decryption by file
     * @param $filename
     * @return string
     */
    public function decryptFile(string $filename): string
    {
        return $this->decrypt(file_get_contents($filename));
    }

    /**
     * Content decryption
     * @param $data string Content of decrypted file
     * @return string
     */
    public function decrypt(string $data): string
    {
        return Crypt::decrypt($data, $this->getContentEncryptionKey());
    }

    /**
     * Set new password for user key file and store it
     * @param $password string
     * @param $filename string
     * @return string
     */
    public function updateUserKeyFile(string $password, string $filename): string
    {
        if (($userKey = file_put_contents($filename, $this->updateUserKey($password))) === false) {
            throw new RuntimeException('Cannot save user key to file!');
        }

        return $userKey;
    }

    /**
     * Set new password for user key file
     * @param $password string New password for user key file
     * @return string
     */
    public function updateUserKey(string $password): string
    {
        return Crypt::encrypt($this->getContentEncryptionKey(), $password);
    }
}
