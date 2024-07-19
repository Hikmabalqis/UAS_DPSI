const multer = require("multer");

// Set up storage configuration for multer to store files in memory
const storage = multer.memoryStorage();

// Initialize multer with the storage configuration
const upload = multer({ storage: storage });

module.exports = upload;
