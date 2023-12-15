//-------IMPORTS---------//
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt"); //create passwords hashs
const jwt = require("jsonwebtoken");

const app = express();

//config json
app.use(express.json());

//credenciais
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

//Models
const User = require("./models/User");

//-------------------connect database--------------------//
mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPass}@cluster0.r5nuhuk.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("Banco de dados conectado");
  })
  .catch((err) => console.log(err));

//open route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a API!" });
});

//----------------REGISTER USERS---------------//
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  //validations
  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatorio" });
  }

  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatorio" });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatoria" });
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ msg: "As senhas não conferem" });
  }

  //cehck if user exists
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    res.status(422).json({ msg: "Por favor, utilize outro e-mail." });
  }

  //create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  //create User
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: "Usúario criado com sucesso" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: "Houve um erro no servidor" });
  }
});

//------------LOGIN USER---------------------//
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //validations
  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatorio" });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatoria" });
  }

  //check if user exists
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ msg: "Usúario não encontrado" });
  }

  //check if password match
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res.status(200).json({ msg: "Autentificação feita com sucesso", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: "Houve um erro com o servidor" });
  }
});
