<?php declare(strict_types=1);

namespace Temant\AuthManager\Utils {
    /**
     * Cookie Utility Class
     *
     * This class provides methods for working with cookies.
     *
     * @version 1.0.0
     * @author  Emad Almahdi <emad.storm@gmail.com>
     * @link    https://github.com/Slvstar/authy
     * @package Temant\AuthManager\Utils
     */
    class Cookie
    {
        /**
         * Set a cookie.
         *
         * @param string $name The name of the cookie.
         * @param string $value The value to store in the cookie.
         * @param int $expire The expiration time of the cookie (Unix timestamp).
         * @param string $path The path on the server where the cookie will be available.
         * @param string $domain The domain on which the cookie will be available.
         * @param bool $secure Indicates whether the cookie should only be transmitted over HTTPS.
         * @param bool $httponly Indicates whether the cookie should be accessible only through HTTP.
         *
         * @return bool True on success, false on failure.
         */
        public static function set(string $name, string $value, int $expire = 0, string $path = '/', string $domain = '', bool $secure = true, bool $httponly = true): bool
        {
            return setcookie($name, $value, $expire, $path, $domain, $secure, $httponly);
        }

        /**
         * Get the value of a cookie.
         *
         * @param string $name The name of the cookie.
         *
         * @return ?string The cookie value, or null if the cookie is not set.
         */
        public static function get(string $name): ?string
        {
            return $_COOKIE[$name] ?? null;
        }

        /**
         * Check if a cookie exists.
         *
         * @param string $name The name of the cookie.
         *
         * @return bool True if the cookie exists, false otherwise.
         */
        public static function has(string $name): bool
        {
            return isset($_COOKIE[$name]);
        }

        /**
         * Delete a cookie.
         *
         * @param string $name The name of the cookie to delete.
         *
         * @return bool True on successful deletion, false if the cookie doesn't exist.
         */
        public static function delete(string $name): bool
        {
            if (self::has($name)) {
                setcookie($name, '', -1);
                unset($_COOKIE[$name]);
                return true;
            }
            return false;
        }
    }
}