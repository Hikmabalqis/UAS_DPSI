const JWT = require("jsonwebtoken");
const createError = require("http-errors");

function signAccessToken(userId) {
  return new Promise((resolve, reject) => {
    const payload = {}; // Data yang disimpan dalam token
    const secret = process.env.ACCESS_TOKEN_SECRET; // Kunci rahasia untuk enkripsi token
    const options = {
      expiresIn: "1y", // Token akan kadaluarsa dalam 1 tahun
      issuer: "peminjaman-barang", // Penerbit token
      audience: userId, // Pengguna token, dalam hal ini adalah userId
    };
    
    JWT.sign(payload, secret, options, (err, token) => {
      if (err) {
        console.log(err.message);
        reject(createError.InternalServerError()); // Jika terjadi error, reject dengan InternalServerError
        return;
      }
      resolve(token); // Jika berhasil, resolve token
    });
  });
}


function verifyAccessToken(req, res, next) {
  if (!req.headers["authorization"]) return next(createError.Unauthorized()); // Jika tidak ada header authorization, return Unauthorized
  
  const authHeader = req.headers["authorization"];
  const bearerToken = authHeader.split(" ");
  const token = bearerToken[1]; // Mengambil token dari header Authorization
  
  JWT.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
    if (err) {
      const message = err.name === "JsonWebTokenError" ? "Unauthorized" : err.message;
      return next(createError.Unauthorized(message)); // Jika token tidak valid, return Unauthorized
    }
    req.payload = payload; // Menyimpan payload di request object
    next(); // Melanjutkan ke middleware berikutnya
  });
}


module.exports = {
  signAccessToken,
  verifyAccessToken,
};
