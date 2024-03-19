const express = require("express");
const mongoose = require("mongoose");
const routes = require("./routes");
const app = express();

const { PORT = 3001 } = process.env;

mongoose
  .connect("mongodb://127.0.0.1:27017/wtwr_db")
  .then(() => {
    console.log("Connected to DB");
  })
  .catch(console.error);

  app.use((req, res, next) => {
    req.user = {
      _id: "65fa0b06ef37754e265e3207",
    };
    next();
  });

app.use(express.json());

app.use(routes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
