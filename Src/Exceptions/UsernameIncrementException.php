<?php declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {
    use Exception;
    use Throwable;

    class UsernameIncrementException extends Exception implements Throwable
    {
        public function __construct(protected $message = "")
        {
            parent::__construct($message, 10002);
        }
    }
}