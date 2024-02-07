<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use Temant\AuthManager\Storage\StorageInterface;

    class UserManager
    {
        private ?string $user_id = null;
        private ?string $first_name = null;
        private ?string $last_name = null;
        private ?string $email = null;
        private ?string $password = null;
        private ?int $is_activated = null;
        private ?int $is_locked = null;
        private ?string $created_at = null;

        /**
         * Constructs the UserManager object with a storage interface for data access.
         *
         * @param StorageInterface $storage The storage mechanism to be used for data retrieval and manipulation.
         */
        public function __construct(
            private StorageInterface $storage
        ) {
        }

        /**
         * Populates the object with user data for the specified user ID.
         *
         * @param string $userId The unique identifier of the user.
         * @return self|null Returns the instance populated with user data, or null if the user does not exist.
         */
        public function byUserId(string $userId): ?self
        {
            $userData = $this->storage->getRow('authentication_users', ['user_id' => $userId]);

            // If no user data is found, return null.
            if (!$userData) {
                return null;
            }

            // Populate the object properties with user data.
            foreach ($userData as $key => $value) {
                $this->$key = $value;
            }
            return $this;
        }

        // Getter methods for accessing the private properties of the class.
        public function getId(): ?string
        {
            return $this->user_id;
        }

        public function getPassword(): string
        {
            return $this->password;
        }
        public function getFullName(): string
        {
            return sprintf('%s %s', $this->first_name, $this->last_name);
        }
        public function getFirstName(): string
        {
            return $this->first_name;
        }
        public function getLastName(): string
        {
            return $this->last_name;
        }
        public function getEmail(): string
        {
            return $this->email;
        }

        public function getCreatedAt(): string
        {
            return $this->created_at;
        }

        /**
         * Retrieves the UserGroupManager object associated with the user.
         *
         * @return UserGroupManager|null The user group object if available, otherwise null.
         */
        public function getGroup(): ?UserGroupManager
        {
            return (new UserGroupManager($this->storage))->byUserId($this->getId());
        }

        /**
         * Retrieves the GroupPermissionsManager object associated with the user's group.
         *
         * @return GroupPermissionsManager The permissions object for the user's group.
         */
        public function getPermissions(): GroupPermissionsManager
        {
            return new GroupPermissionsManager($this->storage, $this->getGroup()->getId());
        }
    }
}