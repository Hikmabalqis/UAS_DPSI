const Mahasiswa = require("../models/Mahasiswa.model");
const createError = require("http-errors");
const bcrypt = require("bcrypt");
const { signAccessToken } = require("../helpers/jwt_helper");

async function register(req, res, next) {
  try {
    const { nim, nama, email, password } = req.body;
    const userExists = await Mahasiswa.findOne({ where: { email } });

    if (userExists)
      throw createError.Conflict(`Mahasiswa with Email ${email} already exist`);

    const hashedPassword = await bcrypt.hash(password, 10);
    await Mahasiswa.create({
      nim: nim,
      nama: nama,
      email: email,
      password: hashedPassword,
    });

    res.status(201).json({
      status: 201,
      message: "User registered successfully",
    });
  } catch (error) {
    next(error);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    const mahasiswa = await Mahasiswa.findOne({ where: { email } });

    if (!mahasiswa)
      throw createError.NotFound(`Mahasiswa with Email ${email} is Not Found`);

    const passwordMatch = await bcrypt.compare(password, mahasiswa.password);

    if (!passwordMatch) throw createError.Conflict("Invalid Password");

    const accessToken = await signAccessToken(email);

    const response = {
      status: 200,
      message: "success",
      data: {
        email: mahasiswa.email,
        token: accessToken,
      },
    };

    res.status(200).json(response);
  } catch (error) {
    next(error);
  }
}

module.exports = {
  register,
  login,
};
