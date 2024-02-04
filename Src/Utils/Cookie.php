<?php declare(strict_types=1);

namespace Temant\AuthManager\Utils {
    /**
     * Cookie Management Utility Class
     *
     * Offers a comprehensive suite of methods to facilitate the handling of HTTP cookies in a secure and efficient manner. 
     * This class abstracts away the complexities associated with cookie management, providing straightforward functionalities 
     * to set, get, check the existence of, and delete cookies with various security options including HttpOnly and Secure flags, 
     * as well as support for the SameSite attribute to enhance protection against Cross-Site Request Forgery (CSRF) attacks.
     *
     * Key Features:
     * - Easy setting of cookies with extensive options for path, domain, security, and more.
     * - Secure retrieval of cookie values, mitigating the risk of unauthorized access.
     * - Utility functions to check the existence of cookies and delete them, enhancing control over client-side storage.
     * - Implementation of modern best practices for cookie security, including default support for Secure, HttpOnly, and SameSite attributes.
     *
     * Usage:
     * The class provides static methods that can be invoked without needing to instantiate the class, simplifying its usage in various contexts
     * within a PHP application. Whether managing user sessions, storing temporary data, or implementing remember-me functionalities,
     * this utility class serves as a robust foundation for cookie-related operations.
     */
    class Cookie implements CookieInterface
    {
        /**
         * Sets a cookie with enhanced options.
         * 
         * @param string $name Name of the cookie.
         * @param string $value Cookie value.
         * @param int $expires Expiration time (Unix timestamp); 0 indicates a session cookie.
         * @param string $path Path where the cookie is accessible; default is '/' for entire domain.
         * @param string $domain Domain scope for the cookie; prefix with '.' for subdomains.
         * @param bool $secure Set true to transmit cookie over HTTPS only.
         * @param bool $httponly Set true to make cookie HTTP-only, mitigating XSS risk.
         * @param string $samesite Sets SameSite policy: 'None', 'Lax', or 'Strict'.
         *
         * @return bool True on success, false on failure.
         */
        public static function set(string $name, string $value, int $expires = 0, string $path = '/', string $domain = '', bool $secure = true, bool $httponly = true, string $samesite = 'Lax'): bool
        {
            $options = [
                'expires' => $expires,
                'path' => $path,
                'domain' => $domain,
                'secure' => $secure,
                'httponly' => $httponly,
                'samesite' => $samesite
            ];
            return setcookie($name, $value, $options);
        }

        /**
         * Retrieves the value of a specified cookie.
         * 
         * @param string $name The name of the cookie.
         *
         * @return ?string The value of the cookie if set; otherwise, NULL.
         */
        public static function get(string $name): ?string
        {
            return $_COOKIE[$name] ?? null;
        }

        /**
         * Checks whether a specified cookie exists.
         * 
         * @param string $name The name of the cookie to check.
         *
         * @return bool TRUE if the cookie exists, otherwise FALSE.
         */
        public static function has(string $name): bool
        {
            return isset($_COOKIE[$name]);
        }

        /**
         * Deletes a specified cookie by setting its expiration time in the past.
         * 
         * @param string $name The name of the cookie to delete.
         *
         * @return bool TRUE on successful deletion, FALSE if the cookie doesn't exist.
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