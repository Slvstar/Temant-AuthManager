<?php declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {
    use Exception;
    use Throwable;

    class EmailNotValidException extends Exception implements Throwable
    {
        public function __construct(protected $message = "The selected Email is not valid")
        {
            parent::__construct($message, 10000);
        }
    }
}