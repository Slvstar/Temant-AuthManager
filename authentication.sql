-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Värd: localhost:3306
-- Tid vid skapande: 08 feb 2024 kl 16:33
-- Serverversion: 8.2.0
-- PHP-version: 8.3.2

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Databas: `authentication`
--

-- --------------------------------------------------------

--
-- Tabellstruktur `authentication_attempts`
--

CREATE TABLE `authentication_attempts` (
  `id` int NOT NULL,
  `user_id` int NOT NULL,
  `success` tinyint NOT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `ip_address` varchar(255) NOT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumpning av Data i tabell `authentication_attempts`
--

INSERT INTO `authentication_attempts` (`id`, `user_id`, `success`, `reason`, `ip_address`, `user_agent`, `created_at`) VALUES
(14, 1, 1, NULL, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36', '2024-02-08 12:37:17');

-- --------------------------------------------------------

--
-- Tabellstruktur `authentication_configurations`
--

CREATE TABLE `authentication_configurations` (
  `config_key` varchar(255) NOT NULL,
  `config_value` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumpning av Data i tabell `authentication_configurations`
--

INSERT INTO `authentication_configurations` (`config_key`, `config_value`) VALUES
('allow_multi_users_with_same_email', 'true'),
('allow_username_increment', 'true'),
('mail_activation_token_lifetime', '3'),
('mail_verify', 'enabled'),
('password_min_length', '3'),
('password_require_lowercase', 'true'),
('password_require_numeric', 'true'),
('password_require_special', 'true'),
('password_require_uppercase', 'true'),
('remember_me_cookie_name', 'remember_me'),
('remember_me_token_lifetime', '13600');

-- --------------------------------------------------------

--
-- Tabellstruktur `authentication_permissions`
--

CREATE TABLE `authentication_permissions` (
  `id` int NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumpning av Data i tabell `authentication_permissions`
--

INSERT INTO `authentication_permissions` (`id`, `name`, `description`) VALUES
(1, 'Write', 'Write Permission to CMS?');

-- --------------------------------------------------------

--
-- Tabellstruktur `authentication_roles`
--

CREATE TABLE `authentication_roles` (
  `id` int NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumpning av Data i tabell `authentication_roles`
--

INSERT INTO `authentication_roles` (`id`, `name`, `description`) VALUES
(1, 'Admin', 'Admin Role?');

-- --------------------------------------------------------

--
-- Tabellstruktur `authentication_role_permissions`
--

CREATE TABLE `authentication_role_permissions` (
  `role_id` int NOT NULL,
  `permission_id` int NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumpning av Data i tabell `authentication_role_permissions`
--

INSERT INTO `authentication_role_permissions` (`role_id`, `permission_id`) VALUES
(1, 1);

-- --------------------------------------------------------

--
-- Tabellstruktur `authentication_tokens`
--

CREATE TABLE `authentication_tokens` (
  `id` int NOT NULL,
  `user_id` int NOT NULL,
  `selector` varchar(32) NOT NULL,
  `validator` text NOT NULL,
  `type` varchar(255) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumpning av Data i tabell `authentication_tokens`
--

INSERT INTO `authentication_tokens` (`id`, `user_id`, `selector`, `validator`, `type`, `expires_at`, `created_at`) VALUES
(1, 1, '76a4a70af3b8f083c09195f0a48a2054', '$2y$10$m6/NwzTOP9Ey8ADMZfyo2uaxlDkfdiKJmEiMVz8Bk0XIBcgOUadFG', 'email_activation', '2024-02-11 09:22:24', '2024-02-08 09:22:24'),
(2, 4, 'b41ed412a3a5a063e0198b2e3a07c9a8', '$2y$10$6OkjY.pv9rWjii5BCA6KA.gIQgrWCoq7CMCwtC1r930beWyoU9PNe', 'email_activation', '2024-02-11 09:32:35', '2024-02-08 09:32:35'),
(3, 10, '25dbb589714b77d6917aefa824999210', '$2y$10$qs5l14fmqEpWzKG1oZSuS.5lNYswz8XrR/vm9quIP0o1bg4NYUgfa', 'email_activation', '2024-02-11 13:14:50', '2024-02-08 13:14:50'),
(4, 11, '9204f58b8d802b6abe8ce4fa1be42a20', '$2y$10$CBLH/46LbPL9DylJxewtCepstZulbVcgkLnAucfvBg817zt/IDlgO', 'email_activation', '2024-02-11 13:14:53', '2024-02-08 13:14:53'),
(5, 12, 'e8cc1538e9aff9b62b77477320a97007', '$2y$10$5jV6gEFwpPDpby7EtCtynOnOKwSQEZCBADTtwWFVg4gf9wPocekRy', 'email_activation', '2024-02-11 13:27:29', '2024-02-08 13:27:29'),
(6, 13, '0c4e2fb86ebbb73152a1a66c69ad0658', '$2y$10$PMNCsSj278DsgNbEHfZY4umv8Eg1VB0a/SPmzuze3ciBgVuYmMdX.', 'email_activation', '2024-02-11 13:30:16', '2024-02-08 13:30:16'),
(7, 1, 'fb11ee14b22e6b534879add9c1581900', '$2y$10$9VruNdruGbe1h03trgjgWu0nIr21RhhEG.u.T460plHubFvYcO8b6', 'remember_me', '2061-05-04 13:37:17', '2024-02-08 13:37:17'),
(8, 14, '1db8e27e3ff663578e9fabbc14ec2a08', '$2y$10$K6D9WmVajFwHYDlyyWvFWOZNctDvKXQWZwSQt3sYZUMkFIcOgsV26', 'email_activation', '2024-02-11 13:44:32', '2024-02-08 13:44:32'),
(9, 15, '87135333ce33da715e2453e6a5aac49d', '$2y$10$Twt0mgZxccveoAFRqQBYgu.zKCGUnyrnfkyQQBq15Q6/jdDEY3d1a', 'email_activation', '2024-02-11 13:47:25', '2024-02-08 13:47:25'),
(10, 16, '9038bc827277dbb3094be6e55896eb24', '$2y$10$O3oUDoVIhHYRaVeMQchUGeZB1xpOHAQuBP5qS573ODR8q/lnZz4Om', 'email_activation', '2024-02-11 13:48:55', '2024-02-08 13:48:55'),
(11, 17, '20fd7aa6ea186efeb086ed8f4e32cf16', '$2y$10$slQpbiCVGqMXe./iGodTB.PuV4.wQiJLwQqRrwhP44htBGz5ixukq', 'email_activation', '2024-02-11 13:54:45', '2024-02-08 13:54:45'),
(12, 18, '8688b15b0856d2b0670a21e75f304d59', '$2y$10$6UqCpnAuG3bB9Z2J7o/.K.w9HN2HzA6oLoDEhQcXRaW2sVTqy5kcm', 'email_activation', '2024-02-11 13:56:24', '2024-02-08 13:56:24'),
(13, 19, '0b6e2d493bce6917050ed0f70e34354a', '$2y$10$kywnsu/3s6Cq/Rc.8jTowOubH9pK16XED8x5gh0ztA7XNEQLHVCrW', 'email_activation', '2024-02-11 13:56:32', '2024-02-08 13:56:32'),
(14, 20, '37e5a46faf1715dae8e1b1506c87e2ec', '$2y$10$AhnrSYY5N6MdeGKIolPDUOuF2n9uw7iFigIj0Dr6mIbF8E54kI/Iu', 'email_activation', '2024-02-11 13:58:48', '2024-02-08 13:58:48'),
(15, 21, '18c27e420d5bc09f6d54cc4785b72caf', '$2y$10$g8fUHOhK2or5EIH3/pYp5escPtwVZXqeeBav/d3R9xtUUeVdrEsHe', 'email_activation', '2024-02-11 14:00:04', '2024-02-08 14:00:04'),
(16, 22, '8433038f2c7710f4949087d0ff4f32c2', '$2y$10$guXb3L9.ajVX8NSxWU80kODAQY85glv3s3A6eo/zUZ2HUiVc8JFCe', 'email_activation', '2024-02-11 14:30:27', '2024-02-08 14:30:27'),
(17, 23, '593382044c59ee2da5e861b60fc76152', '$2y$10$g9uKUl5Pd08/Lx5TKXBkKO2KjjWiIcF89PxXty4nlz/EMcDFuF25y', 'email_activation', '2024-02-11 14:30:33', '2024-02-08 14:30:33'),
(18, 24, 'b20fc0e484ee0e48f9107b36de86a8a1', '$2y$10$OUj1j1uS54kelhlAeAodZul84nzf7UySEDYQyYfo8QqxaTm4BTIO6', 'email_activation', '2024-02-11 14:31:12', '2024-02-08 14:31:12');

-- --------------------------------------------------------

--
-- Tabellstruktur `authentication_users`
--

CREATE TABLE `authentication_users` (
  `id` int NOT NULL,
  `username` varchar(16) NOT NULL,
  `role_id` int DEFAULT NULL,
  `first_name` varchar(255) NOT NULL,
  `last_name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `is_activated` tinyint NOT NULL DEFAULT '0',
  `is_locked` tinyint NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumpning av Data i tabell `authentication_users`
--

INSERT INTO `authentication_users` (`id`, `username`, `role_id`, `first_name`, `last_name`, `email`, `password`, `is_activated`, `is_locked`, `created_at`) VALUES
(1, 'Emad.A', 1, 'Emad', 'Almahdi', 'emad.storm@gmail.com', '$2y$12$rnXTYoSG51GXw6bZLTzU9eJQ3JwYyjMaiXEdqDC7ICJGe9PGCNRA2', 1, 0, '2024-02-08 09:22:24'),
(4, 'Emado.A', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$0PyVK8h6KFDgNc2kxB6OkOfxxrvmK77v85264ezM/EHU6JRejBQFG', 0, 0, '2024-02-08 09:32:34'),
(10, 'Emado.A2', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$fSxZu5lQ5E0DCAcz1HJ9iOMrX18SyIgUVjlVNuDyrdAB6uoDWZlcC', 0, 0, '2024-02-08 13:14:50'),
(11, 'Emado.A3', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$v8VIbh8io9y6ZLS6.EDp0.GlBn1df/qMA6UkYc3BnI0qRWeX2QS/u', 0, 0, '2024-02-08 13:14:53'),
(12, 'Emado.A4', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$6x1jhzFtrejJa6/fmuPpWeEEIgGgFrA/bZas53uCNlaPNziM1I7vC', 0, 0, '2024-02-08 13:27:29'),
(13, 'Emado.A5', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$Qyfib9YVwameAyZ7puv4Je526tDls/.FjetxFu7B866dB0hrI4qTu', 0, 0, '2024-02-08 13:30:16'),
(14, 'Emado.A6', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$Y1hSAa8nh9BGL45UW9bVgu53umtrifaOMRoVh.KyHBiJYWCnYGfTG', 0, 0, '2024-02-08 13:44:32'),
(15, 'Emado.A7', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$wEGqyQc8QBhVQvuU5ozI6OyORB4AAveZsiEsO3v0S1WXYTPhZqH3q', 0, 0, '2024-02-08 13:47:25'),
(16, 'Emado.A8', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$xdlxACHasvdSaDNoSJMYJeSyDkiqxcE4SxaKno6Y05wATJ8.ZKe5K', 0, 0, '2024-02-08 13:48:55'),
(17, 'Emado.A9', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$IRLxq9TCY8vpDPaYO4TAoO9EzDPPXQr6/XMnKnsZxnDih1bH/zlFO', 0, 0, '2024-02-08 13:54:45'),
(18, 'Emado.A10', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$dpGIKm3iaGbrsx1J9p4Ta.m9TtVoygnIru/Ydan9LlhqNlaPf4Tfi', 0, 0, '2024-02-08 13:56:23'),
(19, 'Emado.A11', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$4Z5jCaW1P6ZCy/kEP2pyP.GYnenGPd4iIKolYwxvn0iidXHsy6Yjy', 0, 0, '2024-02-08 13:56:31'),
(20, 'Emado.A12', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$C8BlDfOLOGLfLzV1s4cAROKhrUzY4uk8ZbE98DNeR0kpC4noNp51i', 0, 0, '2024-02-08 13:58:48'),
(21, 'Emado.A13', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$qSP/NSdYtLYCVa1/CnPSXuY4YhoeRx82q5Q4.UXut8hXGi6NVdmHa', 0, 0, '2024-02-08 14:00:03'),
(22, 'Emado.A14', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$Q25fHbSui6RKNNYeuVFXYuYYBR1U3Trs3IhZBwh8QU9MOM2p2w2b2', 0, 0, '2024-02-08 14:30:26'),
(23, 'Emado.A15', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$ofe.yeYroQp6mE9GHMOREOBNsKevC5dSXppD5H7cvCtCUDCfZ4QiC', 0, 0, '2024-02-08 14:30:33'),
(24, 'Emado.A16', 1, 'Emado', 'Almahdio', 'emad.storm@gmail.como', '$2y$12$mZGA6BwdZfaf9Yk1Aj6Q5Ol7eDcoA3Nnf2m/CeQRqw/CEu9nTy/m.', 0, 0, '2024-02-08 14:31:12');

--
-- Index för dumpade tabeller
--

--
-- Index för tabell `authentication_attempts`
--
ALTER TABLE `authentication_attempts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Index för tabell `authentication_configurations`
--
ALTER TABLE `authentication_configurations`
  ADD PRIMARY KEY (`config_key`);

--
-- Index för tabell `authentication_permissions`
--
ALTER TABLE `authentication_permissions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Index för tabell `authentication_roles`
--
ALTER TABLE `authentication_roles`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `idx_role_name` (`name`);

--
-- Index för tabell `authentication_role_permissions`
--
ALTER TABLE `authentication_role_permissions`
  ADD UNIQUE KEY `idx_role_permission` (`role_id`,`permission_id`),
  ADD KEY `fk_auth_role_permission_permission_id` (`permission_id`);

--
-- Index för tabell `authentication_tokens`
--
ALTER TABLE `authentication_tokens`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Index för tabell `authentication_users`
--
ALTER TABLE `authentication_users`
  ADD PRIMARY KEY (`id`),
  ADD KEY `role_id` (`role_id`);

--
-- AUTO_INCREMENT för dumpade tabeller
--

--
-- AUTO_INCREMENT för tabell `authentication_attempts`
--
ALTER TABLE `authentication_attempts`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT för tabell `authentication_roles`
--
ALTER TABLE `authentication_roles`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT för tabell `authentication_tokens`
--
ALTER TABLE `authentication_tokens`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT för tabell `authentication_users`
--
ALTER TABLE `authentication_users`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=25;

--
-- Restriktioner för dumpade tabeller
--

--
-- Restriktioner för tabell `authentication_attempts`
--
ALTER TABLE `authentication_attempts`
  ADD CONSTRAINT `authentication_attempts_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `authentication_users` (`id`);

--
-- Restriktioner för tabell `authentication_role_permissions`
--
ALTER TABLE `authentication_role_permissions`
  ADD CONSTRAINT `fk_auth_role_permission_permission_id` FOREIGN KEY (`permission_id`) REFERENCES `authentication_permissions` (`id`),
  ADD CONSTRAINT `fk_auth_role_permission_role_id` FOREIGN KEY (`role_id`) REFERENCES `authentication_roles` (`id`);

--
-- Restriktioner för tabell `authentication_tokens`
--
ALTER TABLE `authentication_tokens`
  ADD CONSTRAINT `authentication_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `authentication_users` (`id`);

--
-- Restriktioner för tabell `authentication_users`
--
ALTER TABLE `authentication_users`
  ADD CONSTRAINT `authentication_users_ibfk_1` FOREIGN KEY (`role_id`) REFERENCES `authentication_roles` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;