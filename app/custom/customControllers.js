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