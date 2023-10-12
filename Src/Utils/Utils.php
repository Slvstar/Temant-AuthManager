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
    }
}