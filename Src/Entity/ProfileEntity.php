<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {

    use DateTimeInterface;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\OneToOne;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: 'user_profiles')]
    class ProfileEntity
    {
        #[Id]
        #[GeneratedValue]
        #[Column(name: 'id')]
        private int $id;

        #[OneToOne(targetEntity: UserEntity::class, inversedBy: "profile")]
        private UserEntity $user;

        #[Column(name: 'phone_number', nullable: true)]
        private ?string $phoneNumber = null;

        #[Column(name: 'address', nullable: true)]
        private ?string $address = null;

        #[Column(name: 'city', nullable: true)]
        private ?string $city = null;

        #[Column(name: 'state', nullable: true)]
        private ?string $state = null;

        #[Column(name: 'country', nullable: true)]
        private ?string $country = null;

        #[Column(name: 'postal_code', nullable: true)]
        private ?string $postalCode = null;

        #[Column(name: 'date_of_birth', type: "date", nullable: true)]
        private ?DateTimeInterface $dateOfBirth = null;

        #[Column(name: 'bio', type: "text", nullable: true)]
        private ?string $bio = null;

        #[Column(name: 'profile_picture', nullable: true)]
        private ?string $profilePicture = null;

        public function getId(): int
        {
            return $this->id;
        }

        public function getUser(): UserEntity
        {
            return $this->user;
        }

        public function setUser(UserEntity $user): self
        {
            $this->user = $user;
            return $this;
        }

        public function getPhoneNumber(): ?string
        {
            return $this->phoneNumber;
        }

        public function setPhoneNumber(?string $phoneNumber): self
        {
            $this->phoneNumber = $phoneNumber;
            return $this;
        }

        public function getAddress(): ?string
        {
            return $this->address;
        }

        public function setAddress(?string $address): self
        {
            $this->address = $address;
            return $this;
        }

        public function getCity(): ?string
        {
            return $this->city;
        }

        public function setCity(?string $city): self
        {
            $this->city = $city;
            return $this;
        }

        public function getState(): ?string
        {
            return $this->state;
        }

        public function setState(?string $state): self
        {
            $this->state = $state;
            return $this;
        }

        public function getCountry(): ?string
        {
            return $this->country;
        }

        public function setCountry(?string $country): self
        {
            $this->country = $country;
            return $this;
        }

        public function getPostalCode(): ?string
        {
            return $this->postalCode;
        }

        public function setPostalCode(?string $postalCode): self
        {
            $this->postalCode = $postalCode;
            return $this;
        }

        public function getDateOfBirth(): ?DateTimeInterface
        {
            return $this->dateOfBirth;
        }

        public function setDateOfBirth(?DateTimeInterface $dateOfBirth): self
        {
            $this->dateOfBirth = $dateOfBirth;
            return $this;
        }

        public function getBio(): ?string
        {
            return $this->bio;
        }

        public function setBio(?string $bio): self
        {
            $this->bio = $bio;
            return $this;
        }

        public function getProfilePicture(): ?string
        {
            return $this->profilePicture;
        }

        public function setProfilePicture(?string $profilePicture): self
        {
            $this->profilePicture = $profilePicture;
            return $this;
        }
    }
}