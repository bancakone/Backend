// src/middleware/authMiddleware.js
const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
    // Obtenir le token de l'en-tête (Header)
    const token = req.header('x-auth-token');

    // Vérifier si un token existe
    if (!token) {
        return res.status(401).json({ message: 'Aucun token, autorisation refusée' });
    }

    try {
        // Vérifier le token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Attacher l'utilisateur décodé à l'objet de requête
        req.user = decoded; // Contient { id, email, role }
        next(); // Passer au prochain middleware/route
    } catch (error) {
        res.status(401).json({ message: 'Token non valide' });
    }
};


const authorizeRole = (roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Accès non autorisé' });
        }
        next();
    };
};

module.exports = { auth, authorizeRole };