-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Värd: localhost:3306
-- Tid vid skapande: 07 feb 2024 kl 16:23
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
  `user_id` varchar(255) NOT NULL,
  `success` tinyint NOT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `ip_address` varchar(255) NOT NULL,
  `user_agent` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

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
('allow_multi_users_with_same_user_id', 'true'),
('mail_activation_token_lifetime', '3'),
('mail_verify', 'enabled'),
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
  `user_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `selector` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `validator` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- --------------------------------------------------------

--
-- Tabellstruktur `authentication_users`
--

CREATE TABLE `authentication_users` (
  `user_id` varchar(255) NOT NULL,
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

INSERT INTO `authentication_users` (`user_id`, `first_name`, `last_name`, `email`, `password`, `is_activated`, `is_locked`, `created_at`) VALUES
('Emad.A', 'Emad', 'Almahdi', 'emad@almahdi.se', '$2y$12$XAuGbz/EqWL/WoMnET6iLe28KBtfvwZwXxOH9oCMLWFlG5XFCoOG2', 1, 1, '2024-02-05 12:39:08'),
('Emad.A2', 'Emad', 'Almahdi', 'emad@alddmahfffdi.seg', '$2y$12$1BSu.ZVSL71B.ax7/v4zFOaaCrs0ZY7AAB7tbVwiugCNP36aQepn2', 0, 0, '2024-02-07 14:33:23'),
('Emad.A3', 'Emad', 'Almahdi', 'emad@alddmahfffdi.se', '$2y$12$avB4mzPff2WyhOg2zbFgseZnW2dbPf3ZWu4y5krGNqVkn7KAQnpf2', 0, 0, '2024-02-07 14:42:31');

-- --------------------------------------------------------

--
-- Tabellstruktur `authentication_user_role`
--

CREATE TABLE `authentication_user_role` (
  `id` int NOT NULL,
  `role_id` int NOT NULL,
  `user_id` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumpning av Data i tabell `authentication_user_role`
--

INSERT INTO `authentication_user_role` (`id`, `role_id`, `user_id`) VALUES
(1, 1, 'Emad.A');

--
-- Index för dumpade tabeller
--

--
-- Index för tabell `authentication_attempts`
--
ALTER TABLE `authentication_attempts`
  ADD PRIMARY KEY (`id`);

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
  ADD PRIMARY KEY (`id`);

--
-- Index för tabell `authentication_users`
--
ALTER TABLE `authentication_users`
  ADD PRIMARY KEY (`user_id`),
  ADD UNIQUE KEY `idx_user_id` (`user_id`),
  ADD UNIQUE KEY `idx_user_email` (`email`);

--
-- Index för tabell `authentication_user_role`
--
ALTER TABLE `authentication_user_role`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `idx_user_role` (`user_id`,`role_id`),
  ADD KEY `fk_auth_user_role_role_id` (`role_id`);

--
-- AUTO_INCREMENT för dumpade tabeller
--

--
-- AUTO_INCREMENT för tabell `authentication_attempts`
--
ALTER TABLE `authentication_attempts`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT för tabell `authentication_roles`
--
ALTER TABLE `authentication_roles`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT för tabell `authentication_tokens`
--
ALTER TABLE `authentication_tokens`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT för tabell `authentication_user_role`
--
ALTER TABLE `authentication_user_role`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- Restriktioner för dumpade tabeller
--

--
-- Restriktioner för tabell `authentication_role_permissions`
--
ALTER TABLE `authentication_role_permissions`
  ADD CONSTRAINT `fk_auth_role_permission_permission_id` FOREIGN KEY (`permission_id`) REFERENCES `authentication_permissions` (`id`),
  ADD CONSTRAINT `fk_auth_role_permission_role_id` FOREIGN KEY (`role_id`) REFERENCES `authentication_roles` (`id`);

--
-- Restriktioner för tabell `authentication_user_role`
--
ALTER TABLE `authentication_user_role`
  ADD CONSTRAINT `fk_auth_user_role_role_id` FOREIGN KEY (`role_id`) REFERENCES `authentication_roles` (`id`),
  ADD CONSTRAINT `fk_auth_user_role_user_id` FOREIGN KEY (`user_id`) REFERENCES `authentication_users` (`user_id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
