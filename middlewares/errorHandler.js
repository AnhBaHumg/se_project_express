module.exports = (err, req, res, next) => {
  console.error(err);

  if (!err.statusCode) {
    const { statusCode = 500, message } = err;
    return res.status(statusCode).send({
      message: statusCode === 500 ? "An error occurred on the server" : message,
    });
  } else {
    res.status(err.statusCode).send({ message: err.message });
  }
  next();
};
