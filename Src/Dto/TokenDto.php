<?php declare(strict_types=1);

namespace Temant\AuthManager\Dto {
    /**
     * Represents a secure token with both selector and validator.
     */
    final readonly class TokenDto
    {
        public string $token;

        public function __construct(
            public string $selector,
            public string $hashedValidator,
            public string $plainValidator
        ) {
            $this->token = sprintf("%s:%s", $this->selector, $this->plainValidator);
        }
    }
}