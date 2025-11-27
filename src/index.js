const parser = require("body-parser");
const express = require("express");
const app = express();
const port = 3001;

const negocioRoutes = require("./routes/negocioRoutes");
const usuarioRoutes = require("./routes/usuarioRoutes");
const categoriaRoutes = require("./routes/categoriaRoutes");
const animalRoutes = require("./routes/animal");
const authRoutes = require("./routes/authentication");

const mongoose = require("mongoose");
require("dotenv").config();
app.use(parser.urlencoded({ extended: false })); //permite leer los datos que vienen en la petición
app.use(parser.json()); // transforma los datos a formato JSON //Gestión de las rutas usando el middleware

app.use("/api", animalRoutes);
app.use("/api", authRoutes);
app.use("/api", negocioRoutes);
app.use("/api", usuarioRoutes);
app.use("/api", categoriaRoutes);
app.use(express.json()); //Conexión a la base de datos

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Conexión exitosa"))
  .catch((error) => console.log(error)); //Conexión al puerto

  app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
