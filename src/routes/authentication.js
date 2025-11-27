const express = require("express");
const bcrypt = require("bcrypt");
const router = express.Router(); //manejador de rutas de express
const userSchema = require("../models/user");
const jwt = require("jsonwebtoken");
const verifyToken = require("./validate_token");

//Revisar esta forma de autenticarse https://www.digitalocean.com/community/tutorials/nodejs-jwt-expressjs
router.post("/signup", async (req, res) => {
  const { nombre, correo, contrasenia } = req.body;
  const user = new userSchema({
    nombre: nombre,
    correo: correo,
    contrasenia: contrasenia,
  });
  user.contrasenia = await user.encryptcontrasenia(user.contrasenia);
  await user.save(); //save es un método de mongoose para guardar datos en MongoDB //segundo parámetro: un texto que hace que el código generado sea único //tercer parámetro: tiempo de expiración (en segundos, 24 horas en segundos)
  //primer parámetro: payload - un dato que se agrega para generar el token clave
  const token = jwt.sign({ id: user._id }, process.env.SECRET, {
    expiresIn: 60 * 60 * 24, //un día en segundos
  });
  res.json({
    auth: true,
    token: token,
    user,
  });
});

//inicio de sesión
router.post("/login", async (req, res) => {
  // validaciones
  const { error } = userSchema.validate(req.body.correo, req.body.contrasenia);
  if (error) return res.status(400).json({ error: error.details[0].message });
  //Buscando el usuario por su dirección de correo
  const user = await userSchema.findOne({ correo: req.body.correo });

  //validando si no se encuentra
  if (!user)
    return res.status(400).json({ error: "Usuario o contrasenia incorrectos" });

  //Transformando la contraseña a su valor original para
  //compararla con la contrasenia que se ingresa en el inicio de sesión
if (!user.contrasenia) {
    return res.status(400).json({ error: "Error en la configuración del usuario" });
  }

  // Verificar si la contraseña está hasheada (los hashes de bcrypt empiezan con $2a$, $2b$ o $2y$)
  const isHashed = user.contrasenia.startsWith('$2a$') || 
                   user.contrasenia.startsWith('$2b$') || 
                   user.contrasenia.startsWith('$2y$');
  
  let validPassword = false;
  
  if (isHashed) {
    // La contraseña está hasheada, comparar normalmente
    validPassword = await bcrypt.compare(req.body.contrasenia, user.contrasenia);
  } else {
    // La contraseña está en texto plano (usuarios antiguos), comparar directamente
    // y luego hashearla para actualizar en la base de datos
    if (user.contrasenia === req.body.contrasenia) {
      validPassword = true;
      // Hashear la contraseña y actualizar el usuario
      user.contrasenia = await user.encryptClave(user.contrasenia);
      await user.save();
    }
  }
  let accessToken = null;
  if (!validPassword) {
    return res.status(400).json({ error: "Usuario o contrasenia incorrectos" });
  } else {
    const expiresIn = 24 * 60 * 60;
    accessToken = jwt.sign(
      { id: user._id }, 
      process.env.SECRET, {
      expiresIn: expiresIn
    });

   /*res.json({
      id: user._id,
      usuario: user.usuario,
      correo: user.correo,
      contrasenia: user.contrasenia,
      accessToken: accessToken,
      expiresIn: expiresIn,
    });*/
    
    res.json({accessToken});
  }
});
module.exports = router;
