require("dotenv").config();

const cors = require("cors");
const mongoose = require("mongoose");
const express = require("express");
const helmet = require("helmet");
const { errors } = require("celebrate");
const { createUser, login } = require("./controllers/users");
const { getItems } = require("./controllers/clothingItems");
const auth = require("./middlewares/auth");
const errorHandler = require("./middlewares/errorHandler");
const { requestLogger, errorLogger } = require("./middlewares/logger");

console.log(process.env.NODE_ENV);

const app = express();

mongoose.set("strictQuery", true);
mongoose.connect("mongodb://127.0.0.1:27017/wtwr_db");

const routes = require("./routes");
const { validateNewUser, validateLogin } = require("./middlewares/validation");

app.use(cors());
app.use(express.json());
app.use(helmet());

app.get("/crash-test", () => {
  setTimeout(() => {
    throw new Error("Server will crash now");
  }, 0);
});

app.use(requestLogger);

app.post("/signup", validateNewUser, createUser);
app.post("/signin", validateLogin, login);
app.get("/items", getItems);

app.use(auth);
app.use(routes);
app.use(errorLogger);
app.use(errors());
app.use(errorHandler);

const { PORT = 3001 } = process.env;

app.listen(PORT, () => {
  console.log(`App listening at ${PORT}`);
});
