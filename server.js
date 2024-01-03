const express = require("express");
const cors = require("cors");
const session = require('express-session');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const db = require("./app/models");
require('dotenv').config();

const app = express();
//use cookie parser
app.use(cookieParser('secret'));
//config session
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 // 86400000 1 day
  }
}));

// cross origin with local host 4000
app.use(
  cors({
    origin: [process.env.CORS_URL],
    credentials: true,
    optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
  })
);

// parse requests of content-type - application/json
app.use(express.json());
// parse requests of content-type - application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));
//Config passport middleware
db.sequelize.sync()
  .then(() => {
    console.log("Synced db.");
  })
  .catch((err) => {
    console.log("Failed to sync db: " + err.message);
  });
// passport authentication sets
app.use(passport.initialize());
app.use(passport.session());

// // drop the table if it already exists
// db.sequelize.sync({ force: true }).then(() => {
//   console.log("Drop and re-sync db.");
// });

// Custom error call
app.use((error, req, res, next) => {
  res.status(error.statusCode || 500).json({ message: error.message });
});

// simple route
app.get("/", (req, res) => {
  res.json({ message: "Welcome to students MS application." });
});

require("./app/routes/turorial.routes")(app);

// 404 route
app.use("*", (req, res) => {
  res.status(404).json({ message: "404 page not found! Go-Home" });
});

// set port, listen for requests
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});
