const db = require("../models");
const getHashedPassword = require('../custom/passwordHasher');
const StudentTable = db.Student;
const Op = db.Sequelize.Op;
// Create and Save a new StudentTable
exports.create = (req, res) => {
  // Validate request
  if (!req.body.email) {
    res.status(400).send({
      message: "Email can not be empty!"
    });
    return;
  }

  if (req.body.password !== req.body.confirmPassword) {
    res.status(400).send({
      message: "Passwords does not match!"
    });
    return;
  }

  const hashedPassword = getHashedPassword(req.body.password);

  // Create a StudentTable
  const studentObj = {
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    password: hashedPassword,
    classAt: req.body.classAt,
    schoolFee: req.body.schoolFee,
    // confirmPassword: req.body.confirmPassword
  };

  // Save StudentTable in the database
  StudentTable.create(studentObj)
    .then(data => {
      res.send(data);
    })
    .catch(err => {
      res.status(500).send({
        message:
          err.message || "Some error occurred while creating the StudentTable."
      });
    });
};

// Retrieve all StudentTables from the database.
exports.findAll = (req, res) => {
  const email = req.query.email;
  var condition = email ? { email: { [Op.like]: `%${email}%` } } : null;

  StudentTable.findAll({ where: condition })
    .then(data => {
      res.send(data);
    })
    .catch(err => {
      res.status(500).send({
        message:
          err.message || "Some error occurred while retrieving StudentTables."
      });
    });
};

// Find a single StudentTable with an id
exports.findOne = (req, res) => {
  const email = req.params.email;

  StudentTable.findByPk(email)
    .then(data => {
      if (data) {
        res.send(data);
      } else {
        res.status(404).send({
          message: `Cannot find StudentTable with id=${email}.`
        });
      }
    })
    .catch(err => {
      res.status(500).send({
        message: "Error retrieving StudentTable with email=" + email
      });
    });
};

// Update a StudentTable by the id in the request
exports.update = (req, res) => {
  const email = req.params.email;

  StudentTable.update(req.body, {
    where: { email: email }
  })
    .then(num => {
      if (num == 1) {
        res.send({
          message: "StudentTable was updated successfully."
        });
      } else {
        res.send({
          message: `Cannot update StudentTable with id=${id}. Maybe StudentTable was not found or req.body is empty!`
        });
      }
    })
    .catch(err => {
      res.status(500).send({
        message: "Error updating StudentTable with id=" + id
      });
    });
};

// Delete a StudentTable with the specified id in the request
exports.delete = (req, res) => {
  const email = req.params.email;

  StudentTable.destroy({
    where: { email: email }
  })
    .then(num => {
      if (num == 1) {
        res.send({
          message: "StudentTable was deleted successfully!"
        });
      } else {
        res.send({
          message: `Cannot delete StudentTable with id=${id}. Maybe StudentTable was not found!`
        });
      }
    })
    .catch(err => {
      res.status(500).send({
        message: "Could not delete StudentTable with id=" + id
      });
    });
};

// Delete all StudentTables from the database.
exports.deleteAll = (req, res) => {
  StudentTable.destroy({
    where: {},
    truncate: false
  })
    .then(nums => {
      res.send({ message: `${nums} StudentTables were deleted successfully!` });
    })
    .catch(err => {
      res.status(500).send({
        message:
          err.message || "Some error occurred while removing all StudentTables."
      });
    });
};

// find all published StudentTable
exports.findAllPublished = (req, res) => {
  StudentTable.findAll({ where: { published: true } })
    .then(data => {
      res.send(data);
    })
    .catch(err => {
      res.status(500).send({
        message:
          err.message || "Some error occurred while retrieving StudentTables."
      });
    });
};
