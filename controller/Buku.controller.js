const Buku = require("../models/Buku.model");
const createError = require("http-errors");
const getImageUrl = require("../helpers/get_image_url");

async function getAllBuku(req, res, next) {
  try {
    const bukuList = await Buku.findAll();

    const response = {
      status: 200,
      message: "success",
      data: bukuList.map((buku) => ({
        id: buku.id,
        judul: buku.judul,
        pengarang: buku.pengarang,
        sinopsis: buku.sinopsis,
        status: buku.status,
        imageUrl: getImageUrl(req.protocol, req.get("host"), buku),
      })),
    };

    res.json(response);
  } catch (error) {
    next(error);
  }
}

async function getBukuById(req, res, next) {
  try {
    const { id } = req.params;

    const buku = await Buku.findByPk(id);
    if (!buku)
      throw createError.NotFound(`Buku with Buku ID ${id} is Not Found`);

    const response = {
      status: 200,
      message: "success",
      data: {
        id: buku.id,
        judul: buku.judul,
        pengarang: buku.pengarang,
        sinopsis: buku.sinopsis,
        status: buku.status,
        imageUrl: getImageUrl(req.protocol, req.get("host"), buku),
      },
    };

    res.status(200).json(response);
  } catch (error) {
    next(error);
  }
}

async function addBuku(req, res, next) {
  const { judul, pengarang, sinopsis, status } = req.body;
  const image = req.file ? req.file.buffer : null;

  console.log(judul);
  try {
    const buku = await Buku.create({
      judul,
      pengarang,
      sinopsis,
      status,
      image,
    });

    const response = {
      status: 201,
      message: "added",
      data: {
        id: buku.id,
        judul: buku.judul,
        pengarang: buku.pengarang,
        sinopsis: buku.sinopsis,
        status: buku.status,
        imageUrl: getImageUrl(req.protocol, req.get("host"), buku),
      },
    };

    res.status(201).json(response);
  } catch (error) {
    next(error);
  }
}

async function getBukuImage(req, res, next) {
  const { id } = req.params;

  try {
    const buku = await Buku.findByPk(id, {
      attributes: ["image"],
    });

    if (!buku || !buku.image)
      throw createError.NotFound(`Buku with Buku ID ${id} is Not Found`);

    res.setHeader("Content-Type", "image/jpeg");
    res.send(buku.image);
  } catch (error) {
    next(error);
  }
}

async function editBuku(req, res, next) {
  const { id } = req.params;
  const { judul, pengarang, sinopsis, status } = req.body;
  const image = req.file ? req.file.buffer : null; // Read the file if provided

  try {
    const buku = await Buku.findByPk(id);

    if (!buku)
      throw createError.NotFound(`Buku with Buku ID ${id} is Not Found`);

    if (judul) buku.judul = judul;
    if (pengarang) buku.pengarang = pengarang;
    if (sinopsis) buku.sinopsis = sinopsis;
    if (status) buku.status = status;

    if (image) {
      buku.image = image;
    }

    await buku.save();

    const response = {
      status: 200,
      message: "Buku updated successfully",
      data: {
        id: buku.id,
        judul: buku.judul,
        pengarang: buku.pengarang,
        sinopsis: buku.sinopsis,
        status: buku.status,
        imageUrl: getImageUrl(req.protocol, req.get("host"), buku),
      },
    };

    res.json(response);
  } catch (error) {
    next(error);
  }
}

async function updateStatus(req, res, next) {
  try {
    const { id } = req.params;

    const buku = await Buku.findByPk(id);
    if (!buku)
      throw createError.NotFound(`Buku with Buku ID ${id} is Not Found`);

    buku.status = buku.status === "tersedia" ? "dipinjam" : "tersedia";

    await buku.save();

    const response = {
      status: 200,
      message: "Buku updated successfully",
      data: {
        id: buku.id,
        judul: buku.judul,
        pengarang: buku.pengarang,
        sinopsis: buku.sinopsis,
        status: buku.status,
        imageUrl: getImageUrl(req.protocol, req.get("host"), buku),
      },
    };

    res.status(200).json(response);
  } catch (error) {
    next(error);
  }
}

async function deleteBuku(req, res, next) {
  try {
    const { id } = req.params;

    const buku = await Buku.findByPk(id);
    if (!buku)
      throw createError.NotFound(`Buku with Buku ID ${id} is Not Found`);

    await buku.destroy();

    res.status(200).json({
      status: 200,
      message: "deleted",
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  getAllBuku,
  addBuku,
  getBukuImage,
  getBukuById,
  editBuku,
  deleteBuku,
  updateStatus,
};
