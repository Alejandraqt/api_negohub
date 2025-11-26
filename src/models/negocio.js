const mongoose = require("mongoose"); // importando el componente mongoose

const negocioSchema = mongoose.Schema({
    razonSocial: {
        type: String,
        required: true,
    },
    descripcion: {
        type: String,
        required: false,
    },
    telefono: {
        type: String,
        required: true,
    },
    correo: {
        type: String,
        required: true,
        unique: true
    },
    idUsuario: {
        type: mongoose.Schema.Types.ObjectId, 
        ref: "Usuario",
        required: true,
    },
    idCategoria: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Categoria",
        required: true,
    }
});

module.exports = mongoose.model("Negocio", negocioSchema);


/*
formato para creacion en Postman 

{
    "razonSocial": "",
    "descripcion": "",
    "telefono": "",
    "correo": "",
    "idUsuario": "",
    "idCategoria": "",
}

*/