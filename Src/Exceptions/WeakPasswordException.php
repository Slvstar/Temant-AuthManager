<?php declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {
    use Exception;
    use Throwable;

    class WeakPasswordException extends Exception implements Throwable
    {
        public function __construct(protected $message = "")
        {
            parent::__construct($message, 10003);
        }
    }
}