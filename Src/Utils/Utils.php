<?php declare(strict_types=1);

namespace Temant\AuthManager\Utils {
    class Utils
    {
        public static function IP(): string
        {
            if (getenv('REMOTE_ADDR')) {
                $ipAddress = getenv('REMOTE_ADDR');
            } elseif (getenv('HTTP_CLIENT_IP')) {
                $ipAddress = getenv('HTTP_CLIENT_IP');
            } elseif (getenv('HTTP_X_FORWARDED_FOR')) {
                $ipAddress = getenv('HTTP_X_FORWARDED_FOR');
            } elseif (getenv('HTTP_X_FORWARDED')) {
                $ipAddress = getenv('HTTP_X_FORWARDED');
            } elseif (getenv('HTTP_FORWARDED_FOR')) {
                $ipAddress = getenv('HTTP_FORWARDED_FOR');
            } elseif (getenv('HTTP_FORWARDED')) {
                $ipAddress = getenv('HTTP_FORWARDED');
            } else {
                $ipAddress = '127.0.0.1';
            }

            $ipAddress = explode(',', $ipAddress)[0];

            return $ipAddress;
        }

        public static function domain(): string
        {
            return $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . '/';
        }

        /**
         * Detect the type of device from the user agent string.
         * 
         * @return string Device type: 'Mobile', 'Tablet', 'Desktop', or 'Unknown'.
         */
        public static function getDeviceType(): string
        {
            $userAgent = $_SERVER['HTTP_USER_AGENT'];

            if (preg_match('/mobile|android|iphone|ipod/i', $userAgent)) {
                return 'Mobile';
            }

            if (preg_match('/ipad|tablet/i', $userAgent)) {
                return 'Tablet';
            }

            if (preg_match('/windows|macintosh|linux/i', $userAgent)) {
                return 'Desktop';
            }

            return 'Unknown'; // If no match is found
        }

        /**
         * Perform a simple GeoIP lookup using the client's IP address and a free service.
         * 
         * @return string|null Location as 'City, Country' or null if not found.
         */
        public static function GeoIP(): ?string
        {
            $ipAddress = self::getClientIP();

            $url = "http://ip-api.com/json/{$ipAddress}?fields=status,city,country";

            $response = file_get_contents($url);
            if ($response === false) {
                return null; // Failed to fetch GeoIP data
            }

            $data = json_decode($response, true);
            if (isset($data['status']) && $data['status'] === 'success') {
                return "{$data['city']}, {$data['country']}";
            }

            return null; // No valid location found
        }

        /**
         * Helper function to get the client's IP address.
         * 
         * @return string Client's IP address.
         */
        private static function getClientIP(): string
        {
            if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
                return $_SERVER['HTTP_CLIENT_IP'];
            } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]; // Handle proxies
            } else {
                return $_SERVER['REMOTE_ADDR'];
            }
        }
    }
}