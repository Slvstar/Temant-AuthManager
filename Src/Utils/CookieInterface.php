<?php declare(strict_types=1);

namespace Temant\AuthManager\Utils {
    /**
     * Cookie Management Interface
     *
     * Defines the contract for cookie management functionalities, ensuring consistency and reliability
     * in handling cookies across different implementations.
     */
    interface CookieInterface
    {
        /**
         * Sets a cookie with specified parameters and options.
         * 
         * @param string $name The name of the cookie to set.
         * @param string $value The value to be stored in the cookie.
         * @param int $expires The expiration time as a Unix timestamp. Zero means "until the browser is closed".
         * @param string $path Specifies the path on the domain where the cookie will work. Use '/' for the whole domain.
         * @param string $domain Specifies the domain where the cookie is available. To make the cookie available on all subdomains then the domain must be prefixed with a dot like '.example.com'.
         * @param bool $secure If TRUE, the cookie will only be set if a secure connection exists.
         * @param bool $httponly If set to TRUE, the cookie will be accessible only through the HTTP protocol, preventing potential XSS attacks.
         * @param string $samesite Prevents the browser from sending this cookie along with cross-site requests. Accepts 'None', 'Lax', and 'Strict'.
         *
         * @return bool Returns TRUE on success or FALSE on failure.
         */
        public static function set(
            string $name,
            string $value,
            int $expires = 0,
            string $path = '/',
            string $domain = '',
            bool $secure = true,
            bool $httponly = true,
            string $samesite = 'Lax'
        ): bool;

        /**
         * Retrieves the value of a specified cookie.
         * 
         * @param string $name The name of the cookie.
         *
         * @return ?string The value of the cookie if set; otherwise, NULL.
         */
        public static function get(string $name): ?string;

        /**
         * Checks whether a specified cookie exists.
         * 
         * @param string $name The name of the cookie to check.
         *
         * @return bool TRUE if the cookie exists, otherwise FALSE.
         */
        public static function has(string $name): bool;

        /**
         * Deletes a specified cookie by setting its expiration time in the past.
         * 
         * @param string $name The name of the cookie to delete.
         *
         * @return bool TRUE on successful deletion, FALSE if the cookie doesn't exist.
         */
        public static function delete(string $name): bool;
    }
}