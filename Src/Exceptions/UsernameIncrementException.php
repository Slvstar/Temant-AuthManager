<?php declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {
    /**
     * Class UsernameIncrementException
     * 
     * This exception is thrown when there is an issue with incrementing or generating a unique username.
     */
    class UsernameIncrementException extends \Exception implements \Throwable
    {
        public function __construct(string $message = "")
        {
            parent::__construct($message, 10002);
        }
    }
}