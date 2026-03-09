<?php

declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {

    /**
     * Thrown when a login is attempted on a locked account.
     */
    class AccountLockedException extends \Exception implements \Throwable
    {
        public function __construct(string $message = "This account has been locked. Please contact support.")
        {
            parent::__construct($message, 10005);
        }
    }
}
