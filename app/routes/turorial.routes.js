module.exports = app => {
  const studentcontroller = require("../controllers/studentdb.controller.js");

  var router = require("express").Router();

  // Create a new Tutorial
  router.post("/", studentcontroller.create);//worked

  // Retrieve all studentcontroller
  router.get("/", studentcontroller.findAll);//working

  // Retrieve all published studentcontroller
  router.get("/findstudents", studentcontroller.findAllPublished);//working

  // Retrieve a single Tutorial with id
  router.get("/:id", studentcontroller.findOne);//working

  // Update a Tutorial with id
  router.put("/:id", studentcontroller.update);//working

  // Delete a Tutorial with id
  router.delete("/:id", studentcontroller.delete);//worked

  // Delete all studentcontroller
  router.delete("/", studentcontroller.deleteAll);//worked

  app.use('/api/students', router);
};
