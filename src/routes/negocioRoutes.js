const express = require("express");
const router = express.Router(); //Manejador de rutas de express
const negocioSchema = require("../models/negocio");

//Nuevo negocio
router.post("/negocio", (req, res) => {
    const negocio = negocioSchema(req.body);
    negocio
        .save()
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});

//Consultar todos los negocios
router.get("/negocio", (req, res) => {
    negocioSchema.find()
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});

//Modificar el nombre de un negocio por su id
router.put("/negocio/:id", (req, res) => {
    const { id } = req.params;
    const { razonSocial, descripcion, telefono, correo } = req.body;
    negocioSchema
        .updateOne({ _id: id }, {
            $set: { razonSocial, descripcion, telefono, correo }
        })
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});

//Eliminar un negocio con su id
router.delete("/negocio/:id", (req, res) => {
    const { id } = req.params;
    negocioSchema
        .findByIdAndDelete(id)
        .then((data) => {
            res.json(data);
        })
        .catch((error) => {
            res.json({ message: error });
        });
});

//Buscar negocios por nombre
router.get("/negocio/buscar", (req, res) => {
    const { razonSocial } = req.query;
    negocioSchema.find({ razonSocial: { $regex: razonSocial, $options: "i" } })
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});

//Consulta de negocio por ID
router.get("/negocio/:id", (req, res) => {
    const { id } = req.params;
    negocioSchema.findById(id)
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});



module.exports = router;