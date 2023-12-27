// Student Model
module.exports = (sequelize, Sequelize) => {
  const Student = sequelize.define("student", {
    uuid: {
      type: Sequelize.UUID,
      defaultValue: Sequelize.UUIDV4,
      primaryKey: true
    },
    firstName: {
      type: Sequelize.STRING
    },
    lastName: {
      type: Sequelize.STRING
    },
    email: {
      type: Sequelize.STRING,
      unique: true
    },
    password: {
      type: Sequelize.STRING,
      allowNull: false
    },
    classAt: {
      type: Sequelize.STRING
    },
    schoolFee: {
      type: Sequelize.DECIMAL
    },
  });

  return Student;
};

// // Result Model
// module.exports = (sequelize, Sequelize) => {
//   const Result = sequelize.define("result", {
//     uuid: {
//       type: Sequelize.UUID,
//       defaultValue: Sequelize.UUIDV4,
//       primaryKey: true
//     },
//     subject: {
//       type: Sequelize.STRING
//     },
//     score: {
//       type: Sequelize.INTEGER
//     },
//     // other result details...
//   });

//   return Result;
// };

// // Fees Model
// module.exports = (sequelize, Sequelize) => {
//   const Fee = sequelize.define("fee", {
//     uuid: {
//       type: Sequelize.UUID,
//       defaultValue: Sequelize.UUIDV4,
//       primaryKey: true
//     },
//     amount: {
//       type: Sequelize.DECIMAL
//     },
//     dueDate: {
//       type: Sequelize.DATE
//     },
//     // other fee details...
//   });

//   return Fee;
// };

// // Receipt Model
// module.exports = (sequelize, Sequelize) => {
//   const Receipt = sequelize.define("receipt", {
//     uuid: {
//       type: Sequelize.UUID,
//       defaultValue: Sequelize.UUIDV4,
//       primaryKey: true
//     },
//     amountPaid: {
//       type: Sequelize.DECIMAL
//     },
//     datePaid: {
//       type: Sequelize.DATE
//     },
//     // other receipt details...
//   });

//   return Receipt;
// };

