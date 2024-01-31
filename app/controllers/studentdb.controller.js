let errorArr = [];
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const db = require("../models");
const { getHashedPassword, comparePasswords } = require('../custom/passwordHasher');
const StudentTable = db.Student;
const Op = db.Sequelize.Op;
// Create and Save a new StudentTable
exports.create = (req, res) => {
  const { fullName, email, password } = req.body;
  // validation of field will be done at client side
  if (fullName && email && password) {//email exist
    StudentTable.findOne({ where: { email: email } })
      .then(found => {
        if (found != null) {
          res.status(400).json({ emailError: `Student Email exist!` })
          return;
        } else {
          // will be checking password length, chars using joi
          const hashedPassword = getHashedPassword(password);
          // Create a StudentTable
          const studentObj = {
            fullName,
            email,
            password: hashedPassword,
          };
          // Save StudentTable in the database
          StudentTable.create(studentObj)
            .then(data => {
              res.json({ success: `Student created successfully!`, student: data });
            })
            .catch(err => {
              res.status(500).json({
                message:
                  err.message || "Some error occurred while creating the Student profile."
              });
            });
        }
      })
      .catch(err => {
        res.status(500).json(`${err} occured while checking if ${email} exist!`)
      })
  } else {
    res.status(400).json({ message: "Empty Credentials!" })
  }
};

// SignIn controller
// for the authentication... so one can be registered to make request and
// receive responces from server (called seassioning and cashing)
// will creat a better way to trow error maybe using "connectflash" and 
// will creat a middleware func() to alway check if someone is authenticated
// for a request or responce.
// res.json({ email, password })
// passport strategies sets
passport.serializeUser((user, done) => {
  done(null, user.uuid);
});

passport.deserializeUser((uuid, done) => {
  StudentTable.findOne({ where: { uuid: uuid } })
    .then(user => {
      if (!user) {
        return done(null, false, { message: "Couldn't find user!" });
      }
      done(null, user);
    })
    .catch(err => {
      done(err, false, { message: err });
    });
});

passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
  passReqToCallback: true
}, (req, email, password, done) => {
  StudentTable.findOne({ where: { email: email } })
    .then(user => {
      if (!user)
        return done(null, false, { error: 'Oops! Invalid user.' });
      if (!comparePasswords(password, user.password))
        return done(null, false, { error: 'Oops! Incorrect password.' });
      else
        return done(null, user);
    })
    .catch(err => {
      done(err);
    });
}));

exports.signIn = (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(401).json({ error: info.error });
    }
    // Log in the user
    req.logIn(user, (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      // Send a success response with user information
      return res.status(200).json({
        success: true,
        user: {
          email: user.email,
          fullName: user.fullName
          // Add any other user information you want to send to the client
        },
      });
    });
  })(req, res, next);
};
// confirm user authentication
exports.isAutenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.status(401).send('User not signed-In, SignIn please!')
  }
}
// logout
exports.logOut = (req, res) => {
  req.logout();
  res.status(200).json({ success: true, message: 'Logout successful' });
}

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
  StudentTable.findAll({ where: { isGradguated: true } })
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

