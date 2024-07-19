const { Sequelize } = require("sequelize");
require("dotenv").config();

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: "mysql",
    dialectModule: require("mysql2"),
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000,
    },
    ssl: true,
    dialectOptions: {
      ssl: {
        ca: Buffer.from(process.env.SSL_CERTIFICATE, "base64").toString(
          "ascii"
        ),
      },
    },
  }
);

sequelize
  .authenticate()
  .then(() => {
    console.log("Connected to Database");
  })
  .catch((err) => {
    console.log("Unable to Connect to the Database", err);
  });

module.exports = sequelize;
