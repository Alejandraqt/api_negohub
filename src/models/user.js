const mongoose = require("mongoose"); // importando el componente mongoose
const bcrypt = require("bcrypt"); // importando el componente bcrypt

const userSchema = mongoose.Schema({
  nombre: {
    type: String,
    required: false,
  },
  correo: {
    type: String,
    required: true,
  },
  contrasenia: {
    type: String,
    required: true,
  },
});

userSchema.methods.encryptClave = async (contrasenia) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(contrasenia, salt);
};

module.exports = mongoose.model("User", userSchema);

/*
formato para creacion en Postman 

{
    "nombre": "",
    "correo": "",
    "contraseña": "",
    "rol": ""
    
}

*/