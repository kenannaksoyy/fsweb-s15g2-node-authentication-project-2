const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const authRouter = require("./auth/auth-router.js");
const usersRouter = require("./users/users-router.js");
const { bul , goreBul, idyeGoreBul } = require("./users/users-model.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use("/api/auth", authRouter);
server.use("/api/users", usersRouter);

server.get("/",async(req, res) => {
  res.status(200).json({
    message:"Server Deneme"
  })
});

server.use("*",(req, res) => {
  res.status(404).json({
    message:"Oops Not Found"
  })
});
server.use((err, req, res, next) => { // eslint-disable-line
  res.status(err.status || 500).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;
