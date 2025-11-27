const express = require("express");
const router = express.Router(); //Manejador de rutas de express

const usuarioSchema = require("../models/user"); //Importa el modelo de Mongoose para la coleccion 'usuario'


//Creación de un nuevo usuario
router.post("/usuario", (req, res) => {
    const usuario = new usuarioSchema(req.body);
    usuario
        .save()
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});


//Consulta de todos los usuario
router.get("/usuario", (req, res) => {
    usuarioSchema.find()
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});


//Actualización de un usuario por ID
router.put("/usuario/:id", (req, res) => {
    const { id } = req.params;
    const { nombre, correo, contrasenia } = req.body;
    usuarioSchema
        .updateOne({ _id: id }, {
            $set: { nombre, correo, contrasenia}
        })
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});


//Eliminar un usuario por ID
router.delete("/usuario/:id", (req, res) => {
    const { id } = req.params;
    usuarioSchema
        .findByIdAndDelete(id)
        .then((data) => {
            res.json(data);
        })
        .catch((error) => {
            res.json({ message: error });
        });
});


//Consulta de usuario por ID
router.get("/usuario/:id", (req, res) => {
    const { id } = req.params;
    usuarioSchema.findById(id)
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});

module.exports = router;