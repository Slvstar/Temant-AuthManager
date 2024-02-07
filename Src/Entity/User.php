<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {
    use DateTime;
    use DateTimeInterface;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: 'authentication_users')]
    class User
    {
        #[Id]
        #[Column(name: 'user_id')]
        private string $userId;

        #[Column(name: 'first_name')]
        private string $firstName;

        #[Column(name: 'last_name')]
        private string $lastName;

        #[Column(name: 'email')]
        private string $email;

        #[Column(name: 'password')]
        private string $password;

        #[Column(name: 'is_activated')]
        private bool $isActivated;

        #[Column(name: 'is_locked')]
        private bool $isLocked;

        #[Column(name: 'created_at')]
        private DateTimeInterface $createdAt;

        public function __construct()
        {
            $this->createdAt = new DateTime();
        }
    }
}