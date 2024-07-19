const express = require("express");
const router = express.Router();
const MahasiswaController = require("../controller/Mahasiswa.controller");

router.post("/register", MahasiswaController.register);

router.post("/login", MahasiswaController.login);

module.exports = router;
