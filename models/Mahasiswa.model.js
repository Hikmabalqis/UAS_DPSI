const { Sequelize, DataTypes, Model } = require("sequelize");
const sequelize = require("../helpers/init_mysql"); // Adjust path as necessary

class Mahasiswa extends Model {}

Mahasiswa.init(
  {
    nim: {
      type: DataTypes.CHAR,
      allowNull: false,
      primaryKey: true,
    },
    nama: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
  },
  {
    sequelize,
    modelName: "Mahasiswa",
    tableName: "mahasiswa",
    timestamps: false,
  }
);

module.exports = Mahasiswa;
