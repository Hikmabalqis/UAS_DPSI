const express = require("express");
const router = express.Router();
const { verifyAccessToken } = require("../helpers/jwt_helper"); //verifyAccessToken: Middleware ini memastikan bahwa setiap permintaan harus diautentikasi dengan JWT yang valid.
const PeminjamanController = require("../controller/Peminjaman.controller"); 

router.get("/", verifyAccessToken, PeminjamanController.getAllPeminjaman); 

router.get("/:id", verifyAccessToken, PeminjamanController.getPeminjamanById);

router.post("/", verifyAccessToken, PeminjamanController.addPeminjaman);

router.patch("/:id", verifyAccessToken, PeminjamanController.editPeminjaman);

router.delete("/:id", verifyAccessToken, PeminjamanController.deletePeminjaman);

module.exports = router;
