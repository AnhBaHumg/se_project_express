const user = require("../models/user");

const {
  invalidDataError,
  notFoundError,
  serverError,
} = require("../utils/errors");

function getUsers(req, res) {
  user
    .find({})
    .then((users) => {
      res.status(200).send({ data: users });
    })
    .catch((e) => {
      console.error(e);
      res
        .status(serverError)
        .send({ message: "An error occurred on the server" });
    });
}

function createUser(req, res) {
  const { name, avatar } = req.body;
  user
    .create({ name, avatar })
    .then((newUser) => {
      res.status(200).send({ data: newUser });
    })
    .catch((e) => {
      console.error(e);
      if (e.name === "ValidationError") {
        res.status(invalidDataError).send({ message: "Invalid data" });
      } else if (e.name === "CastError") {
        res.status(invalidDataError).send({ message: "Invalid data" });
      } else {
        res
          .status(serverError)
          .send({ message: "An error occurred on the server" });
      }
    });
}

function getUser(req, res) {
  user
    .findById(req.params.id)
    .orFail()
    .then((specifiedUser) => {
      res.status(200).send({ data: specifiedUser });
    })
    .catch((e) => {
      console.error(e);
      console.log(e.name);
      if (e.name === "ValidationError") {
        res.status(invalidDataError).send({ message: "Invalid data" });
      } else if (e.name === "CastError") {
        res.status(invalidDataError).send({ message: "Invalid data" });
      } else if (e.name === "DocumentNotFoundError") {
        res
          .status(notFoundError)
          .send({ message: "Requested resource not found" });
      } else {
        res
          .status(serverError)
          .send({ message: "An error occurred on the server" });
      }
    });
}

module.exports = { getUsers, createUser, getUser };
