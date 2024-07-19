const sequelize = require("../helpers/init_mysql");
const Buku = require("./Buku.model");
const Mahasiswa = require("./Mahasiswa.model");
const Peminjaman = require("./Peminjaman.model");

Mahasiswa.hasMany(Peminjaman, { foreignKey: "nim", as: "meminjam" });
Buku.hasMany(Peminjaman, { foreignKey: "bukuId", as: "dipinjam" });
Peminjaman.belongsTo(Mahasiswa, { foreignKey: "nim", as: "mahasiswa" });
Peminjaman.belongsTo(Buku, { foreignKey: "bukuId", as: "buku" });

const db = {
  sequelize,
  Buku,
  Mahasiswa,
  Peminjaman,
};

module.exports = db;
