const express = require("express");
const router = express.Router();
const BukuController = require("../controller/Buku.controller");
const upload = require("../middleware/upload");
const { verifyAccessToken } = require("../helpers/jwt_helper");

router.get("/", verifyAccessToken, BukuController.getAllBuku);

router.get("/:id", verifyAccessToken, BukuController.getBukuById);

router.patch(
  "/:id",
  verifyAccessToken,
  upload.single("image"),
  BukuController.editBuku
);

router.patch("/:id/status", verifyAccessToken, BukuController.updateStatus);

router.delete("/:id", verifyAccessToken, BukuController.deleteBuku);

router.post(
  "/",
  verifyAccessToken,
  upload.single("image"),
  BukuController.addBuku
);

router.get("/:id/image", verifyAccessToken, BukuController.getBukuImage);

module.exports = router;
