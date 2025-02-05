CREATE TABLE `apwg_urls_to_check` (
	`apwg_id` INTEGER,
	`apwg_url` TEXT,
	`trials` INTEGER,
	`added_timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE `apwg_all_urls` (
	`id` INTEGER PRIMARY KEY,
	`apwg_id` INTEGER,
	`apwg_url` TEXT,
	`trials` INTEGER,
	`added_timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP,
	`updated_timestamped` DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE `apwg_last_id` (
	`apwg_id` INTEGER
);