const dbConfig = require("../config/db.config.js");

const Sequelize = require("sequelize");
const sequelize = new Sequelize(dbConfig.DB, dbConfig.USER, dbConfig.PASSWORD, {
  host: dbConfig.HOST,
  dialect: dbConfig.dialect,
  // operatorsAliases: false,

  pool: {
    max: dbConfig.pool.max,
    min: dbConfig.pool.min,
    acquire: dbConfig.pool.acquire,
    idle: dbConfig.pool.idle
  }
});

// doing it wrongly
// Define associations
// Student.hasMany(Result, { as: "results" });
// Result.belongsTo(Student, {
//   foreignKey: "studentId",
//   as: "student",
// });

// Student.hasMany(Fee, { as: "fees" });
// Fee.belongsTo(Student, {
//   foreignKey: "studentId",
//   as: "student",
// });

// Fee.hasOne(Receipt, { as: "receipt" });
// Receipt.belongsTo(Fee, {
//   foreignKey: "feeId",
//   as: "fee",
// });

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;

db.Student = require("./studentdb.model.js")(sequelize, Sequelize);
// db.Result = require("./studentdb.model.js")(sequelize, Sequelize);
// db.Fee = require("./studentdb.model.js")(sequelize, Sequelize);
// db.Receipt = require("./studentdb.model.js")(sequelize, Sequelize);
module.exports = db;
