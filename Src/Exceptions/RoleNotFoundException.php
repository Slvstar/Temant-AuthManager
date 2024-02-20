<?php declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {
    use Exception;
    use Throwable;

    class RoleNotFoundException extends Exception implements Throwable
    {
        public function __construct(protected $message = "The selected Role ID doesn't exist")
        {
            parent::__construct($message, 10001);
        }
    }
}