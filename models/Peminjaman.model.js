const { Sequelize, DataTypes, Model } = require("sequelize");
const sequelize = require("../helpers/init_mysql");
const Mahasiswa = require("../models/Mahasiswa.model");
const Buku = require("../models/Buku.model");

class Peminjaman extends Model {
  toJSON() {
    const attributes = { ...this.get() };
    delete attributes.nim;
    delete attributes.bukuId;
    return attributes;
  }
}

Peminjaman.init(
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      allowNull: false,
      primaryKey: true,
    },
    nim: {
      type: DataTypes.CHAR,
      allowNull: false,
      references: {
        model: Mahasiswa,
        key: "nim",
      },
    },
    bukuId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: Buku,
        key: "id",
      },
    },
    tanggalPeminjaman: {
      type: DataTypes.DATEONLY,
      allowNull: false,
    },
    tanggalKembali: {
      type: DataTypes.DATEONLY,
      allowNull: false,
    },
  },
  {
    sequelize,
    modelName: "Peminjaman",
    tableName: "peminjaman",
    timestamps: false,
  }
);

module.exports = Peminjaman;
