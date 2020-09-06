<?php
namespace CryptLibrary;

use RuntimeException;

class UserCrypt
{
    private $userKey;
    private $userKeyPassword;

    /**
     * User constructor
     * @param $userKeyFilename string Filename of user key file
     * @param $userKeyPassword string Password for user key file
     */
    public function __construct($userKeyFilename, $userKeyPassword)
    {
        $this->userKey = file_get_contents($userKeyFilename);
        $this->userKeyPassword = $userKeyPassword;
    }

    /**
     * Content encryption
     * @param $data string Content of encrypted file
     * @return string
     */
    public function encrypt($data): string
    {
        return Crypt::encrypt($data, $this->getContentEncryptionKey());
    }

    /**
     * Content encryption by file
     * @param $filename
     * @param null $encryptedFilename
     * @return string
     * @throws RuntimeException
     */
    public function encryptFile($filename, $encryptedFilename = null): string
    {
        $encryptedData = $this->encrypt(file_get_contents($filename));

        if ($encryptedFilename && !file_put_contents($encryptedFilename, $encryptedData)) {
            throw new RuntimeException('Cannot save encrypted data to file!');
        }

        return $encryptedData;
    }

    /**
     * Content decryption
     * @param $data string Content of decrypted file
     * @return string
     */
    public function decrypt($data): string
    {
        return Crypt::decrypt($data, $this->getContentEncryptionKey());
    }

    /**
     * Content decryption by file
     * @param $filename
     * @return string
     */
    public function decryptFile($filename): string
    {
        return $this->decrypt(file_get_contents($filename));
    }

    /**
     * Set new password for user key file
     * @param $password string New password for user key file
     * @return string
     */
    public function updateUserKey($password): string
    {
        return Crypt::encrypt($this->getContentEncryptionKey(), $password);
    }

    /**
     * Set new password for user key file and store it
     * @param $password
     * @param $filename
     * @return string
     */
    public function updateUserKeyFile($password, $filename): string
    {
        if (($userKey = file_put_contents($filename, $this->updateUserKey($password))) === false) {
            throw new RuntimeException('Cannot save user key to file!');
        }

        return $userKey;
    }

    /**
     * Get content encryption key
     * @return string
     */
    private function getContentEncryptionKey(): string
    {
        return Crypt::decrypt($this->userKey, $this->userKeyPassword);
    }
}