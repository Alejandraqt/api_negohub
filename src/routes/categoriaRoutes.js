const express = require("express");
const router = express.Router(); //Manejador de rutas de express

const categoriaSchema = require("../models/categoria"); //Importa el modelo de Mongoose para la coleccion 'categoria'


//Creación de una nueva categoría
router.post("/categoria", (req, res) => {
    const categoria = new categoriaSchema(req.body);
    categoria
        .save()
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});


//Consulta de todas las categoorías
router.get("/categoria", (req, res) => {
    categoriaSchema.find()
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});


//Actualización de una categoría por ID
router.put("/categoria/:id", (req, res) => {
    const { id } = req.params;
    const { nombre } = req.body;
    categoriaSchema
        .updateOne({ _id: id }, {
            $set: { nombre }
        })
        .then((data) => res.json(data))
        .catch((error) => res.json({ message: error }));
});


//Eliminar una categoría por ID
router.delete("/categoria/:id", (req, res) => {
    const { id } = req.params;
    categoriaSchema
        .findByIdAndDelete(id)
        .then((data) => {
            res.json(data);
        })
        .catch((error) => {
            res.json({ message: error });
        });
});

module.exports = router;