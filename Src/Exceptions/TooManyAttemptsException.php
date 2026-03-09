<?php

declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {

    /**
     * Thrown when a user exceeds the maximum allowed failed login attempts.
     */
    class TooManyAttemptsException extends \Exception implements \Throwable
    {
        public function __construct(string $message = "Too many failed login attempts. Please try again later.")
        {
            parent::__construct($message, 10004);
        }
    }
}
