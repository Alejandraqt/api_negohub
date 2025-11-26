const mongoose = require("mongoose"); //importa librebía Mongoose para gestionar la base de datos MongoDB

//Esquema que define la estructura de doucumentos para la tabla 'categoria'
const categoriaSchema = mongoose.Schema({
    nombre: {
        type: String, // Tipo de dato
        required: true, //Este campo es obligatorio
    }
});

//Exporta el modelo para poder usarlo en rutas
module.exports = mongoose.model("categoria", categoriaSchema);


/*
formato para creacion en Postman 

{
    "nombre": ""
}

*/