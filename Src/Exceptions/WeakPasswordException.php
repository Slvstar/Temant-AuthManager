<?php declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {
    /**
     * Class WeakPasswordException
     * 
     * This exception is thrown when a password is considered too weak.
     */
    class WeakPasswordException extends \Exception implements \Throwable
    {
        public function __construct(string $message = "")
        {
            parent::__construct($message, 10003);
        }
    }
}