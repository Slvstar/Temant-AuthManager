<?php declare(strict_types=1);

namespace Temant\AuthManager\Exceptions {
    /**
     * Class RoleNotFoundException
     * 
     * This exception is thrown when a non-existent Role ID is referenced.
     */
    class RoleNotFoundException extends \Exception implements \Throwable
    {
        public function __construct(string $message = "The selected Role ID doesn't exist")
        {
            parent::__construct($message, 10001);
        }
    }
}