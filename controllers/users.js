const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/user");
const { devSecret } = require("../utils/config");
const { NODE_ENV, JWT_SECRET } = process.env;

const BadRequestError = require("../utils/errors/BadRequestError");
const NotFoundError = require("../utils/errors/NotFoundError");
const ConflictError = require("../utils/errors/ConflicError");
const UnauthorizedError = require("../utils/errors/UnathorizedError");

function getCurrentUser(req, res, next) {
  User.findById(req.user._id)
    .then((currentUser) => {
      if (!currentUser) {
        return Promise.reject(new Error("User not found"));
      }
      return res.status(200).send({ data: currentUser });
    })
    .catch((e) => {
      console.error(e);

      if (e.name === "CastError") {
        next(new BadRequestError("Invalid input data"));
      } else if (err.message === "User not found") {
        next(new NotFoundError("User not found"));
      } else {
        next(e);
      }
    });
}

function updateCurrentUser(req, res, next) {
  const { name, avatar } = req.body;

  User.findByIdAndUpdate(
    req.user._id,
    { name, avatar },
    { new: true, runValidators: true },
  )
    .orFail()
    .then((updatedUser) => {
      res.status(200).send({ data: updatedUser });
    })
    .catch((e) => {
      console.error(e);

      if (e.name === "ValidationError") {
        next(new BadRequestError("Invalid input data"));
      } else if (err.name === "CastError") {
        next(new BadRequestError("Invalid input format"));
      } else if (err.name === "DocumentNotFoundError") {
        next(new NotFoundError("Cannot update nonexistent user"));
      } else {
        next(e);
      }
    });
}

function createUser(req, res, next) {
  const { name, avatar, email, password } = req.body;

  User.findOne({ email })
    .then((existingUser) => {
      if (existingUser) {
        throw new Error("Email already in use");
      }
      return bcrypt.hash(password, 10);
    })
    .then((hash) => {
      return User.create({ name, avatar, email, password: hash }).then(
        (newUser) => {
          const response = newUser.toObject();
          delete response.password;

          res.status(200).send({ data: response });
        },
      );
    })
    .catch((e) => {
      console.error(e);

      if (e.name === "ValidationError") {
        next(new BadRequestError("Invalid input data"));
      } else if (err.name === "CastError") {
        next(new BadRequestError("Invalid input format"));
      } else if (err.message === "Email already in use") {
        next(new ConflictError("Email already in use"));
      } else {
        next(e);
      }
    });
}

function login(req, res, next) {
  const { email, password } = req.body;

  if (!email || !password) {
    next(new BadRequestError("Invalid email or password"));
  }

  return User.findUserByCredentials(email, password)
    .then((existingUser) => {
      const token = jwt.sign(
        { _id: existingUser._id },
        NODE_ENV === "production" ? JWT_SECRET : devSecret,
        {
          expiresIn: "7d",
        },
      );

      res.status(200).send({ data: token });
    })
    .catch((e) => {
      console.error(e);

      if (e.message === "Incorrect email or password") {
        next(new UnauthorizedError("Incorrect email or password"));
      } else {
        next(err);
      }
    });
}

module.exports = {
  getCurrentUser,
  updateCurrentUser,
  createUser,
  login,
};
