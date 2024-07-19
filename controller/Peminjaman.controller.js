const { Peminjaman, Mahasiswa, Buku } = require("../models/index");
const createError = require("http-errors");

async function getAllPeminjaman(req, res, next) {
  try {
    const peminjamans = await Peminjaman.findAll({
      include: [
        {
          model: Mahasiswa,
          as: "mahasiswa",
          attributes: ["nim", "nama"],
        },
        {
          model: Buku,
          as: "buku",
          attributes: ["id", "judul"],
        },
      ],
    });

    res.json({
      status: 200,
      message: "success",
      data: peminjamans,
    });
  } catch (error) {
    next(error);
  }
}

async function getPeminjamanById(req, res, next) {
  const { id } = req.params;

  try {
    const peminjaman = await Peminjaman.findByPk(id, {
      include: [
        {
          model: Mahasiswa,
          as: "mahasiswa",
          attributes: ["nim", "nama"],
        },
        {
          model: Buku,
          as: "buku",
          attributes: ["id", "judul"],
        },
      ],
    });

    if (!peminjaman)
      throw createError.NotFound(
        `Peminjaman with Peminjaman ID ${id} is Not Found`
      );

    res.json({
      status: 200,
      message: "success",
      data: peminjaman,
    });
  } catch (error) {
    next(error);
  }
}

async function addPeminjaman(req, res, next) {
  const { nim, bukuId, tanggalPeminjaman, tanggalKembali } = req.body;

  try {
    const newPeminjaman = await Peminjaman.create({
      nim,
      bukuId,
      tanggalPeminjaman,
      tanggalKembali,
    });

    const response = await Peminjaman.findByPk(newPeminjaman.id, {
      include: [
        {
          model: Mahasiswa,
          as: "mahasiswa",
          attributes: ["nim", "nama"],
        },
        {
          model: Buku,
          as: "buku",
          attributes: ["id", "judul"],
        },
      ],
    });

    res.status(201).json({
      status: 201,
      message: "Peminjaman added successfully",
      data: response,
    });
  } catch (error) {
    next(error);
  }
}

async function editPeminjaman(req, res, next) {
  const { id } = req.params;
  const { nim, bukuId, tanggalPeminjaman, tanggalKembali } = req.body;

  try {
    const peminjaman = await Peminjaman.findByPk(id);

    if (!peminjaman)
      throw createError.NotFound(
        `Peminjaman with Peminjaman ID ${id} is Not Found`
      );

    peminjaman.nim = nim || peminjaman.nim;
    peminjaman.bukuId = bukuId || peminjaman.bukuId;
    peminjaman.tanggalPeminjaman =
      tanggalPeminjaman || peminjaman.tanggalPeminjaman;
    peminjaman.tanggalKembali = tanggalKembali || peminjaman.tanggalKembali;

    await peminjaman.save();

    const response = await Peminjaman.findByPk(peminjaman.id, {
      include: [
        {
          model: Mahasiswa,
          as: "mahasiswa",
          attributes: ["nim", "nama"], // Adjust the attributes as needed
        },
        {
          model: Buku,
          as: "buku",
          attributes: ["id", "judul"], // Adjust the attributes as needed
        },
      ],
    });

    res.json({
      status: 200,
      message: "Peminjaman updated successfully",
      data: response,
    });
  } catch (error) {
    next(error);
  }
}

async function deletePeminjaman(req, res, next) {
  const { id } = req.params;

  try {
    const peminjaman = await Peminjaman.findByPk(id);

    if (!peminjaman)
      throw createError.NotFound(
        `Peminjaman with Peminjaman ID ${id} is Not Found`
      );

    await peminjaman.destroy();

    res.json({
      status: 200,
      message: "Peminjaman deleted successfully",
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  getAllPeminjaman,
  getPeminjamanById,
  addPeminjaman,
  editPeminjaman,
  deletePeminjaman,
};
