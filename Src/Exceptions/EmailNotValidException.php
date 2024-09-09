<?php declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {
    /**
     * Class EmailNotValidException
     * 
     * This exception is thrown when an invalid email is encountered. 
     */
    class EmailNotValidException extends \Exception implements \Throwable
    {
        public function __construct(string $message = "The selected Email is not valid")
        {
            parent::__construct($message, 10000);
        }
    }
}