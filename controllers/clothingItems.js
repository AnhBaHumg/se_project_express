const clothingItem = require("../models/clothingItem");
const BadRequestError = require("../utils/errors/BadRequestError");
const ForbiddenError = require("../utils/errors/ForbiddenError");
const NotFoundError = require("../utils/errors/NotFoundError");

function getItems(req, res, next) {
  clothingItem
    .find({})
    .then((items) => {
      res.status(200).send({ data: items });
    })
    .catch((e) => {
      next(e);
    });
}

function createItem(req, res, next) {
  const { name, weather, imageUrl } = req.body;

  const owner = req.user._id;

  clothingItem
    .create({ name, weather, imageUrl, owner })
    .then((item) => {
      res.status(200).send({ data: item });
    })
    .catch((e) => {
      if (e.name === "ValidationError") {
        next(new BadRequestError("Invalid input data"));
      } else if (e.name === "CastError") {
        next(new BadRequestError("Invalid input format"));
      } else {
        next(e);
      }
    });
}

function deleteItem(req, res, next) {
  return clothingItem
    .findById(req.params.id)
    .orFail()
    .then((item) => {
      if (!item.owner.equals(req.user._id)) {
        throw new Error("You are not authorized to delete this item");
      }
      return item.deleteOne().then(() => {
        res.status(200).send({ data: item, message: "Item deleted" });
      });
    })
    .catch((e) => {
      if (e.name === "CastError") {
        next(new BadRequestError("Invalid input format"));
      } else if (e.name === "DocumentNotFoundError") {
        next(new NotFoundError("Cannot delete nonexistent item"));
      } else if (e.message === "You are not authorized to delete this item") {
        next(new ForbiddenError("You are not authorized to delete this item"));
      } else {
        next(e);
      }
    });
}

function likeItem(req, res, next) {
  clothingItem
    .findByIdAndUpdate(
      req.params.id,
      { $addToSet: { likes: req.user._id } },
      { new: true },
    )
    .orFail()
    .then((item) => {
      res.status(200).send(item);
    })
    .catch((e) => {
      if (e.name === "CastError") {
        next(new BadRequestError("Invalid input format"));
      } else if (e.name === "DocumentNotFoundError") {
        next(new NotFoundError("Cannot like nonexistent item"));
      } else {
        next(e);
      }
    });
}

function dislikeItem(req, res, next) {
  clothingItem
    .findByIdAndUpdate(
      req.params.id,
      { $pull: { likes: req.user._id } },
      { new: true },
    )
    .orFail()
    .then((item) => {
      res.status(200).send(item);
    })
    .catch((e) => {
      if (e.name === "CastError") {
        next(new BadRequestError("Invalid input format"));
      } else if (e.name === "DocumentNotFoundError") {
        next(new NotFoundError("Cannot dislike nonexistent item"));
      } else {
        next(e);
      }
    });
}

module.exports = { getItems, createItem, deleteItem, likeItem, dislikeItem };
