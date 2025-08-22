-- MySQL dump 10.13  Distrib 9.3.0, for macos15.2 (arm64)
--
-- Host: localhost    Database: gov_feedback
-- ------------------------------------------------------
-- Server version	9.3.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `feedback`
--

DROP TABLE IF EXISTS `feedback`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `feedback` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `subject` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `priority` enum('low','medium','high') DEFAULT 'medium',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `upvotes` int DEFAULT '0',
  `resolved` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `feedback_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=32 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `feedback`
--

LOCK TABLES `feedback` WRITE;
/*!40000 ALTER TABLE `feedback` DISABLE KEYS */;
/*!40000 ALTER TABLE `feedback` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `notices`
--

DROP TABLE IF EXISTS `notices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `notices` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `content` text NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `notices`
--

LOCK TABLES `notices` WRITE;
/*!40000 ALTER TABLE `notices` DISABLE KEYS */;
/*!40000 ALTER TABLE `notices` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `upvotes`
--

DROP TABLE IF EXISTS `upvotes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `upvotes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `feedback_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_upvote` (`user_id`,`feedback_id`),
  UNIQUE KEY `unique_user_feedback` (`user_id`,`feedback_id`),
  KEY `fk_feedback_upvotes` (`feedback_id`),
  CONSTRAINT `fk_feedback_upvotes` FOREIGN KEY (`feedback_id`) REFERENCES `feedback` (`id`) ON DELETE CASCADE,
  CONSTRAINT `upvotes_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `upvotes`
--

LOCK TABLES `upvotes` WRITE;
/*!40000 ALTER TABLE `upvotes` DISABLE KEYS */;
/*!40000 ALTER TABLE `upvotes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `role` enum('admin','citizen') DEFAULT 'citizen',
  `reset_token` varchar(255) DEFAULT NULL,
  `reset_token_expires` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'John Doe','john@example.com','$2b$10$n2LCnWKks1uGVU8RGUdybOt/Y6ZrXnAtoqH8E2s2u/.BvZleHDZNO','admin',NULL,NULL),(2,'sudeep','sudeepexample.com','$2b$10$ResPJz1qM056iKCef.sPvO0n7LoDoEc6El13z7.tn1HZBGEX.V5Zm','citizen',NULL,NULL),(4,'Jane Citizen','jane@example.com','$2b$10$cRr8gTebf7fo9nC/qMwlXurkFWtxxnpW3vG38BauKYPGdZQuiSx3u','citizen',NULL,NULL),(5,'Citizen Test','citizen1@example.com','$2b$10$cu2NOerbV02O8dsfcqRUFeWiUwY28my80PWohxmFcnpr03RW8h7qq','citizen',NULL,NULL),(7,'Sudeep Regmi','sudeepregmi343@gmail.com','$2a$12$VTPSHWBwNfVolU3PJxxYJe/RYYyTqQa9Vfu1yryzeFM.Wj8tB.nVK','admin',NULL,NULL),(9,'ronaldo','ronaldo@example.com','$2b$10$5tz/UQUiPCypUKI8GGBvge5NoMdGx5PpKqJZ42pNk6J99YttqPO.S','citizen',NULL,NULL),(11,'Sudeep Regmi','sudeepofficial01@gmail.com','$2b$10$CGffue1k2fGI2p8KTz0bueLVycKa.oEuhXqac3q1xFZPp8lKOFCsG','citizen',NULL,NULL),(12,'Laxmi Paudel','laxmisharma3480@gmail.com','$2b$10$dOeuAuapt6iPZk8Zdh/dnuQv4JnmwIyEqosoFnQ1.qvmGxrCfSiMK','citizen',NULL,NULL),(13,'Basanta Khadka','Basanta@gmail.com','$2b$10$rECVVKnd1AGpPySkpGJ1zuhFtH/lOL65VtZl57ZB1ThbvICl0FXHO','citizen',NULL,NULL),(14,'admin','admin@example.com','$2a$12$PGRzX2jeSIXIfXTcTnT0NOIdSP4FXMD8otAXXIQ6w.if/C7wQequm','admin',NULL,NULL),(15,'jim','jim123@gmail.cccom','$2b$10$DcITMh7MFspLnxbRtlWYsekTAR9ezON3YkCKf5EdLFKQmoOxRErnC','citizen',NULL,NULL);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-08-22 23:08:14
