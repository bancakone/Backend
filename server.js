// server.js
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise'); // Assurez-vous d'avoir mysql2 installé
const bcrypt = require('bcryptjs');     // Assurez-vous d'avoir bcryptjs installé
const jwt = require('jsonwebtoken');    // Assurez-vous d'avoir jsonwebtoken installé
const { auth, authorizeRole } = require('./middleware/authMiddleware');

const app = express();
const port = process.env.PORT || 5000;

// Middleware pour parser le JSON des requêtes
app.use(express.json());

// Configuration de la base de données
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
};

// Fonction pour obtenir une connexion à la base de données
async function getConnection() {
    return await mysql.createConnection(dbConfig);
}

// Fonction pour tester la connexion à la base de données au démarrage
async function testDbConnection() {
    try {
        const connection = await getConnection();
        console.log('🎉 Connecté à la base de données MySQL avec succès !');
        connection.end(); // Ferme la connexion de test
    } catch (error) {
        console.error('❌ Erreur de connexion à la base de données :', error.message);
        // Si la connexion échoue, l'application ne peut pas fonctionner, donc nous arrêtons le processus
        process.exit(1);
    }
}

// Appeler la fonction de test au démarrage du serveur
testDbConnection();

// --- Routes d'authentification ---

// Route d'inscription
app.post('/api/auth/register', async (req, res) => {
    const { nom, prenom, email, password, role } = req.body;

    if (!nom || !prenom || !email || !password || !role) {
        return res.status(400).json({ message: 'Tous les champs sont requis.' });
    }

    let connection;
    try {
        connection = await getConnection();

        const [existingUsers] = await connection.execute('SELECT id FROM Users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'Cet email est déjà enregistré.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // --- AJOUTEZ CETTE LIGNE POUR LE DÉBOGAGE ---
        console.log(`Tentative d'insertion pour l'utilisateur ${email} avec le rôle: ${role}`);
        
        const [result] = await connection.execute(
            'INSERT INTO Users (nom, prenom, email, motDePasse, role) VALUES (?, ?, ?, ?, ?)',
            [nom, prenom, email, hashedPassword, role]
        );

        const token = jwt.sign(
            { id: result.insertId, email, role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({
            message: 'Utilisateur enregistré avec succès !',
            token,
            user: { id: result.insertId, nom, prenom, email, role }
        });

    } catch (error) {
        console.error('Erreur lors de l\'inscription :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de l\'inscription.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route de connexion
app.post('/api/auth/login', async (req, res) => {
    const { email, motDePasse } = req.body;

    // Validation simple des entrées
    if (!email || !motDePasse) {
        return res.status(400).json({ message: 'Email et mot de passe sont requis.' });
    }

    let connection;
    try {
        connection = await getConnection();

        // Chercher l'utilisateur par email
        const [users] = await connection.execute('SELECT id, nom, prenom, email, motDePasse, role FROM Users WHERE email = ?', [email]);
        const user = users[0];

        if (!user) {
            return res.status(401).json({ message: 'Email ou mot de passe incorrect.' });
        }

        // Comparer le mot de passe fourni avec le mot de passe haché
        const isMatch = await bcrypt.compare(motDePasse, user.motDePasse);

        if (!isMatch) {
            return res.status(401).json({ message: 'Email ou mot de passe incorrect.' });
        }

        // Générer un token JWT
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: 'Connexion réussie.',
            token,
            user: { id: user.id, nom: user.nom, prenom: user.prenom, email: user.email, role: user.role }
        });

    } catch (error) {
        console.error('Erreur lors de la connexion :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la connexion.' });
    } finally {
        if (connection) connection.end();
    }
});


// --- NOUVELLES ROUTES POUR LA GESTION DES CLASSES ---

// Générer un code de classe unique aléatoire
const generateClassCode = () => {
    return Math.random().toString(36).substring(2, 8).toUpperCase(); // Ex: "ABCDEF"
};

// Route pour créer une nouvelle classe (accessible uniquement aux professeurs)
app.post('/api/classes', auth, authorizeRole(['Professeur']), async (req, res) => {
    const { nom, description } = req.body;
    const professeur_id = req.user.id; // L'ID du professeur vient du token JWT

    if (!nom) {
        return res.status(400).json({ message: 'Le nom de la classe est requis.' });
    }

    let connection;
    try {
        connection = await getConnection();
        let classCode = generateClassCode();
        let codeExists = true;

        // Assurer l'unicité du code de classe
        while(codeExists) {
            const [existingCode] = await connection.execute('SELECT id FROM Classes WHERE code = ?', [classCode]);
            if (existingCode.length === 0) {
                codeExists = false;
            } else {
                classCode = generateClassCode(); // Générer un nouveau code si déjà pris
            }
        }

        const [result] = await connection.execute(
            'INSERT INTO Classes (nom, description, code, professeur_id) VALUES (?, ?, ?, ?)',
            [nom, description, classCode, professeur_id]
        );

        // Inscrire le professeur à sa propre classe avec le rôle "Professeur" dans UserClasses
        await connection.execute(
            'INSERT INTO UserClasses (user_id, class_id, role_dans_classe) VALUES (?, ?, ?)',
            [professeur_id, result.insertId, 'Professeur']
        );

        res.status(201).json({
            message: 'Classe créée avec succès !',
            class: {
                id: result.insertId,
                nom,
                description,
                code: classCode,
                professeur_id
            }
        });

    } catch (error) {
        console.error('Erreur lors de la création de la classe :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la création de la classe.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir toutes les classes créées par le professeur connecté
app.get('/api/classes/professeur', auth, authorizeRole(['Professeur']), async (req, res) => {
    const professeur_id = req.user.id;

    let connection;
    try {
        connection = await getConnection();
        const [classes] = await connection.execute(
            'SELECT id, nom, description, code FROM Classes WHERE professeur_id = ?',
            [professeur_id]
        );
        res.status(200).json(classes);
    } catch (error) {
        console.error('Erreur lors de la récupération des classes du professeur :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir toutes les classes auxquelles un utilisateur (étudiant/prof) est inscrit
app.get('/api/classes/me', auth, async (req, res) => {
    const userId = req.user.id;

    let connection;
    try {
        connection = await getConnection();
        // Jointure pour récupérer les détails des classes auxquelles l'utilisateur est inscrit
        const [classes] = await connection.execute(
            `SELECT
                C.id, C.nom, C.description, C.code,
                U.nom as professeurNom, U.prenom as professeurPrenom,
                UC.role_dans_classe
            FROM UserClasses UC
            JOIN Classes C ON UC.class_id = C.id
            JOIN Users U ON C.professeur_id = U.id
            WHERE UC.user_id = ?`,
            [userId]
        );
        res.status(200).json(classes);
    } catch (error) {
        console.error('Erreur lors de la récupération des classes de l\'utilisateur :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur.' });
    } finally {
        if (connection) connection.end();
    }
});


// Route pour un étudiant pour rejoindre une classe avec un code
app.post('/api/classes/join', auth, authorizeRole(['Etudiant']), async (req, res) => {
    const { code } = req.body;
    const studentId = req.user.id; // L'ID de l'étudiant vient du token JWT

    if (!code) {
        return res.status(400).json({ message: 'Le code de la classe est requis.' });
    }

    let connection;
    try {
        connection = await getConnection();

        // Trouver la classe par son code
        const [classes] = await connection.execute('SELECT id FROM Classes WHERE code = ?', [code]);
        const classToJoin = classes[0];

        if (!classToJoin) {
            return res.status(404).json({ message: 'Classe introuvable avec ce code.' });
        }

        // Vérifier si l'étudiant est déjà inscrit
        const [existingEnrollment] = await connection.execute(
            'SELECT id FROM UserClasses WHERE user_id = ? AND class_id = ?',
            [studentId, classToJoin.id]
        );
        if (existingEnrollment.length > 0) {
            return res.status(409).json({ message: 'Vous êtes déjà inscrit à cette classe.' });
        }

        // Inscrire l'étudiant à la classe
        await connection.execute(
            'INSERT INTO UserClasses (user_id, class_id, role_dans_classe) VALUES (?, ?, ?)',
            [studentId, classToJoin.id, 'Etudiant']
        );

        res.status(200).json({ message: 'Classe rejointe avec succès !' });

    } catch (error) {
        console.error('Erreur lors de l\'inscription à la classe :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de l\'inscription à la classe.' });
    } finally {
        if (connection) connection.end();
    }
});


// Route pour créer une annonce (accessible uniquement aux professeurs)
app.post('/api/announcements', auth, authorizeRole(['Professeur']), async (req, res) => {
    const { class_id, titre, contenu } = req.body;
    const professeur_id = req.user.id; // L'ID du professeur vient du token JWT

    if (!class_id || !titre || !contenu) {
        return res.status(400).json({ message: 'L\'ID de la classe, le titre et le contenu sont requis.' });
    }

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si le professeur est bien le propriétaire de la classe
        const [classes] = await connection.execute('SELECT id FROM Classes WHERE id = ? AND professeur_id = ?', [class_id, professeur_id]);
        if (classes.length === 0) {
            return res.status(403).json({ message: 'Vous n\'êtes pas autorisé à publier une annonce dans cette classe.' });
        }

        const [result] = await connection.execute(
            'INSERT INTO Announcements (class_id, professeur_id, titre, contenu) VALUES (?, ?, ?, ?)',
            [class_id, professeur_id, titre, contenu]
        );

        res.status(201).json({
            message: 'Annonce créée avec succès !',
            announcement: {
                id: result.insertId,
                class_id,
                professeur_id,
                titre,
                contenu
            }
        });

    } catch (error) {
        console.error('Erreur lors de la création de l\'annonce :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la création de l\'annonce.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir toutes les annonces d'une classe spécifique
app.get('/api/announcements/:classId', auth, async (req, res) => {
    const { classId } = req.params;
    const userId = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si l'utilisateur est inscrit à cette classe (en tant qu'étudiant ou professeur)
        const [enrollment] = await connection.execute(
            'SELECT id FROM UserClasses WHERE user_id = ? AND class_id = ?',
            [userId, classId]
        );
        if (enrollment.length === 0) {
            // Si pas inscrit, vérifier s'il est le professeur de la classe
            const [isProfessor] = await connection.execute('SELECT id FROM Classes WHERE id = ? AND professeur_id = ?', [classId, userId]);
            if (isProfessor.length === 0) {
                 return res.status(403).json({ message: 'Accès non autorisé à cette classe.' });
            }
        }

        const [announcements] = await connection.execute(
            `SELECT A.id, A.titre, A.contenu, A.created_at, U.nom as professeurNom, U.prenom as professeurPrenom
             FROM Announcements A
             JOIN Users U ON A.professeur_id = U.id
             WHERE A.class_id = ?
             ORDER BY A.created_at DESC`,
            [classId]
        );
        res.status(200).json(announcements);

    } catch (error) {
        console.error('Erreur lors de la récupération des annonces :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération des annonces.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour partager/créer une documentation (accessible uniquement aux professeurs)
app.post('/api/documentations', auth, authorizeRole(['Professeur']), async (req, res) => {
    const { class_id, titre, description, file_path } = req.body;
    const professeur_id = req.user.id; // L'ID du professeur vient du token JWT

    if (!class_id || !titre) {
        return res.status(400).json({ message: 'L\'ID de la classe et le titre sont requis.' });
    }

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si le professeur est bien le propriétaire de la classe
        const [classes] = await connection.execute('SELECT id FROM Classes WHERE id = ? AND professeur_id = ?', [class_id, professeur_id]);
        if (classes.length === 0) {
            return res.status(403).json({ message: 'Vous n\'êtes pas autorisé à partager de la documentation dans cette classe.' });
        }

        const [result] = await connection.execute(
            'INSERT INTO Documentations (class_id, professeur_id, titre, description, file_path) VALUES (?, ?, ?, ?, ?)',
            [class_id, professeur_id, titre, description, file_path]
        );

        res.status(201).json({
            message: 'Documentation partagée avec succès !',
            documentation: {
                id: result.insertId,
                class_id,
                professeur_id,
                titre,
                description,
                file_path
            }
        });

    } catch (error) {
        console.error('Erreur lors du partage de la documentation :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors du partage de la documentation.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir toute la documentation d'une classe spécifique
app.get('/api/documentations/:classId', auth, async (req, res) => {
    const { classId } = req.params;
    const userId = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si l'utilisateur est inscrit à cette classe (en tant qu'étudiant ou professeur)
        const [enrollment] = await connection.execute(
            'SELECT id FROM UserClasses WHERE user_id = ? AND class_id = ?',
            [userId, classId]
        );
        if (enrollment.length === 0) {
            // Si pas inscrit, vérifier s'il est le professeur de la classe
            const [isProfessor] = await connection.execute('SELECT id FROM Classes WHERE id = ? AND professeur_id = ?', [classId, userId]);
            if (isProfessor.length === 0) {
                 return res.status(403).json({ message: 'Accès non autorisé à cette documentation.' });
            }
        }

        const [documentations] = await connection.execute(
            `SELECT D.id, D.titre, D.description, D.file_path, D.created_at, U.nom as professeurNom, U.prenom as professeurPrenom
             FROM Documentations D
             JOIN Users U ON D.professeur_id = U.id
             WHERE D.class_id = ?
             ORDER BY D.created_at DESC`,
            [classId]
        );
        res.status(200).json(documentations);

    } catch (error) {
        console.error('Erreur lors de la récupération de la documentation :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération de la documentation.' });
    } finally {
        if (connection) connection.end();
    }
});
// Route pour assigner une tâche (accessible uniquement aux professeurs)
app.post('/api/tasks', auth, authorizeRole(['Professeur']), async (req, res) => {
    const { class_id, titre, description, date_limite } = req.body;
    const professeur_id = req.user.id;

    if (!class_id || !titre || !date_limite) {
        return res.status(400).json({ message: 'L\'ID de la classe, le titre et la date limite sont requis.' });
    }

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si le professeur est bien le propriétaire de la classe
        const [classes] = await connection.execute('SELECT id FROM Classes WHERE id = ? AND professeur_id = ?', [class_id, professeur_id]);
        if (classes.length === 0) {
            return res.status(403).json({ message: 'Vous n\'êtes pas autorisé à assigner une tâche dans cette classe.' });
        }

        const [result] = await connection.execute(
            'INSERT INTO Tasks (class_id, professeur_id, titre, description, date_limite) VALUES (?, ?, ?, ?, ?)',
            [class_id, professeur_id, titre, description, date_limite]
        );

        res.status(201).json({
            message: 'Tâche assignée avec succès !',
            task: {
                id: result.insertId,
                class_id,
                professeur_id,
                titre,
                description,
                date_limite
            }
        });

    } catch (error) {
        console.error('Erreur lors de l\'assignation de la tâche :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de l\'assignation de la tâche.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir toutes les tâches d'une classe spécifique (pour professeur et étudiant inscrit)
app.get('/api/tasks/class/:classId', auth, async (req, res) => {
    const { classId } = req.params;
    const userId = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si l'utilisateur est inscrit à cette classe ou en est le professeur
        const [enrollment] = await connection.execute(
            'SELECT id FROM UserClasses WHERE user_id = ? AND class_id = ?',
            [userId, classId]
        );
        const [isProfessor] = await connection.execute('SELECT id FROM Classes WHERE id = ? AND professeur_id = ?', [classId, userId]);

        if (enrollment.length === 0 && isProfessor.length === 0) {
             return res.status(403).json({ message: 'Accès non autorisé à ces tâches.' });
        }

        const [tasks] = await connection.execute(
            `SELECT T.id, T.titre, T.description, T.date_limite, T.created_at, U.nom as professeurNom, U.prenom as professeurPrenom
             FROM Tasks T
             JOIN Users U ON T.professeur_id = U.id
             WHERE T.class_id = ?
             ORDER BY T.date_limite ASC`,
            [classId]
        );
        res.status(200).json(tasks);

    } catch (error) {
        console.error('Erreur lors de la récupération des tâches :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération des tâches.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour soumettre une tâche (accessible uniquement aux étudiants)
app.post('/api/tasks/:taskId/submit', auth, authorizeRole(['Etudiant']), async (req, res) => {
    const { taskId } = req.params;
    const { file_path, content } = req.body;
    const student_id = req.user.id;

    if (!file_path && !content) {
        return res.status(400).json({ message: 'Un chemin de fichier ou un contenu est requis pour la soumission.' });
    }

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si la tâche existe et si l'étudiant est inscrit à la classe de cette tâche
        const [taskInfo] = await connection.execute('SELECT class_id FROM Tasks WHERE id = ?', [taskId]);
        if (taskInfo.length === 0) {
            return res.status(404).json({ message: 'Tâche non trouvée.' });
        }
        const class_id = taskInfo[0].class_id;

        const [enrollment] = await connection.execute(
            'SELECT id FROM UserClasses WHERE user_id = ? AND class_id = ?',
            [student_id, class_id]
        );
        if (enrollment.length === 0) {
            return res.status(403).json({ message: 'Vous n\'êtes pas autorisé à soumettre à cette tâche (non inscrit à la classe).' });
        }

        // Vérifier si une soumission existe déjà pour cette tâche par cet étudiant
        const [existingSubmission] = await connection.execute(
            'SELECT id FROM Submissions WHERE task_id = ? AND student_id = ?',
            [taskId, student_id]
        );

        let result;
        if (existingSubmission.length > 0) {
            // Mise à jour de la soumission existante
            await connection.execute(
                'UPDATE Submissions SET file_path = ?, content = ?, submitted_at = CURRENT_TIMESTAMP WHERE id = ?',
                [file_path, content, existingSubmission[0].id]
            );
            result = { affectedRows: 1 }; // Simuler le résultat pour la réponse
            res.status(200).json({ message: 'Soumission de tâche mise à jour avec succès !' });
        } else {
            // Nouvelle soumission
            [result] = await connection.execute(
                'INSERT INTO Submissions (task_id, student_id, file_path, content) VALUES (?, ?, ?, ?)',
                [taskId, student_id, file_path, content]
            );
            res.status(201).json({ message: 'Tâche soumise avec succès !', submissionId: result.insertId });
        }

    } catch (error) {
        console.error('Erreur lors de la soumission de la tâche :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la soumission de la tâche.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir les soumissions pour une tâche donnée (accessible uniquement aux professeurs)
app.get('/api/tasks/:taskId/submissions', auth, authorizeRole(['Professeur']), async (req, res) => {
    const { taskId } = req.params;
    const professeur_id = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si le professeur est bien le propriétaire de la tâche
        const [taskInfo] = await connection.execute('SELECT id FROM Tasks WHERE id = ? AND professeur_id = ?', [taskId, professeur_id]);
        if (taskInfo.length === 0) {
            return res.status(403).json({ message: 'Vous n\'êtes pas autorisé à voir les soumissions de cette tâche.' });
        }

        const [submissions] = await connection.execute(
            `SELECT S.id, S.file_path, S.content, S.submitted_at, S.grade, S.correction_feedback, U.nom as studentNom, U.prenom as studentPrenom
             FROM Submissions S
             JOIN Users U ON S.student_id = U.id
             WHERE S.task_id = ?
             ORDER BY S.submitted_at ASC`,
            [taskId]
        );
        res.status(200).json(submissions);

    } catch (error) {
        console.error('Erreur lors de la récupération des soumissions :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération des soumissions.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour noter et corriger une soumission (accessible uniquement aux professeurs)
app.put('/api/submissions/:submissionId/grade', auth, authorizeRole(['Professeur']), async (req, res) => {
    const { submissionId } = req.params;
    const { grade, feedback } = req.body;
    const professeur_id = req.user.id;

    if (grade === undefined || feedback === undefined) {
        return res.status(400).json({ message: 'La note et le feedback sont requis.' });
    }

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si le professeur est bien le propriétaire de la tâche associée à cette soumission
        const [submissionInfo] = await connection.execute(
            'SELECT T.professeur_id FROM Submissions S JOIN Tasks T ON S.task_id = T.id WHERE S.id = ?',
            [submissionId]
        );
        if (submissionInfo.length === 0 || submissionInfo[0].professeur_id !== professeur_id) {
            return res.status(403).json({ message: 'Vous n\'êtes pas autorisé à noter cette soumission.' });
        }

        await connection.execute(
            'UPDATE Submissions SET grade = ?, correction_feedback = ? WHERE id = ?',
            [grade, feedback, submissionId]
        );

        res.status(200).json({ message: 'Soumission notée et corrigée avec succès !' });

    } catch (error) {
        console.error('Erreur lors de la notation de la soumission :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la notation de la soumission.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir la soumission d'un étudiant pour une tâche donnée (accessible uniquement à l'étudiant concerné et son professeur)
app.get('/api/submissions/:submissionId', auth, async (req, res) => {
    const { submissionId } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

    let connection;
    try {
        connection = await getConnection();

        const [submission] = await connection.execute(
            `SELECT S.id, S.task_id, S.student_id, S.file_path, S.content, S.submitted_at, S.grade, S.correction_feedback,
                    T.professeur_id, T.titre as taskTitre, T.description as taskDescription, T.date_limite as taskDateLimite,
                    U.nom as studentNom, U.prenom as studentPrenom
             FROM Submissions S
             JOIN Tasks T ON S.task_id = T.id
             JOIN Users U ON S.student_id = U.id
             WHERE S.id = ?`,
            [submissionId]
        );

        if (submission.length === 0) {
            return res.status(404).json({ message: 'Soumission non trouvée.' });
        }

        const sub = submission[0];

        // Vérifier l'autorisation : étudiant propriétaire de la soumission ou professeur de la tâche
        if (userRole === 'Etudiant' && sub.student_id !== userId) {
            return res.status(403).json({ message: 'Vous n\'êtes pas autorisé à voir cette soumission.' });
        }
        if (userRole === 'Professeur' && sub.professeur_id !== userId) {
            return res.status(403).json({ message: 'Vous n\'êtes pas autorisé à voir cette soumission.' });
        }

        res.status(200).json(sub);

    } catch (error) {
        console.error('Erreur lors de la récupération de la soumission spécifique :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération de la soumission.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir toutes les soumissions faites par l'utilisateur connecté (étudiant)
app.get('/api/users/me/submissions', auth, authorizeRole(['Etudiant']), async (req, res) => {
    const student_id = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        const [submissions] = await connection.execute(
            `SELECT S.id, S.task_id, S.file_path, S.content, S.submitted_at, S.grade, S.correction_feedback,
                    T.titre as taskTitre, T.description as taskDescription, T.date_limite as taskDateLimite,
                    C.nom as className, C.id as classId
             FROM Submissions S
             JOIN Tasks T ON S.task_id = T.id
             JOIN Classes C ON T.class_id = C.id
             WHERE S.student_id = ?
             ORDER BY S.submitted_at DESC`,
            [student_id]
        );
        res.status(200).json(submissions);

    } catch (error) {
        console.error('Erreur lors de la récupération des soumissions de l\'étudiant :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération des soumissions de l\'étudiant.' });
    } finally {
        if (connection) connection.end();
    }
});

app.post('/api/messages', auth, async (req, res) => {
    const { receiver_id, class_id, content, message_type } = req.body;
    const sender_id = req.user.id; // L'ID de l'utilisateur connecté est l'expéditeur

    let connection;
    try {
        connection = await getConnection();

        // Validation de base
        if (!content || content.trim() === '') {
            return res.status(400).json({ message: 'Le contenu du message ne peut pas être vide.' });
        }
        if (!['public', 'private'].includes(message_type)) {
            return res.status(400).json({ message: 'Type de message invalide. Doit être "public" ou "private".' });
        }

        if (message_type === 'private') {
            if (!receiver_id) {
                return res.status(400).json({ message: 'L\'ID du destinataire est requis pour un message privé.' });
            }
            // Vérifier que l'expéditeur et le destinataire ne sont pas les mêmes
            if (sender_id === receiver_id) {
                return res.status(400).json({ message: 'Vous ne pouvez pas vous envoyer un message privé à vous-même.' });
            }
            // Vérifier si le destinataire existe (optionnel mais recommandé)
            const [receiverExists] = await connection.execute('SELECT id FROM Users WHERE id = ?', [receiver_id]);
            if (receiverExists.length === 0) {
                return res.status(404).json({ message: 'Destinataire non trouvé.' });
            }
            await connection.execute(
                'INSERT INTO Messages (sender_id, receiver_id, content, message_type) VALUES (?, ?, ?, ?)',
                [sender_id, receiver_id, content, message_type]
            );
            res.status(201).json({ message: 'Message privé envoyé avec succès.' });

        } else if (message_type === 'public') { // message_type === 'public'
            if (!class_id) {
                return res.status(400).json({ message: 'L\'ID de la classe est requis pour un message public.' });
            }
            // Vérifier que l'expéditeur est bien membre de la classe (professeur ou coordinateur)
            const [classMembership] = await connection.execute(
                'SELECT C.id FROM Classes C JOIN ClassMembers CM ON C.id = CM.class_id WHERE C.id = ? AND CM.user_id = ?',
                [class_id, sender_id]
            );
            if (classMembership.length === 0) {
                return res.status(403).json({ message: 'Vous devez être membre de cette classe pour y envoyer un message public.' });
            }
            // Optionnel : Vérifier si l'expéditeur a le rôle approprié pour envoyer des messages publics (Professeur ou Coordinateur)
            const [senderRole] = await connection.execute('SELECT role FROM Users WHERE id = ?', [sender_id]);
            if (senderRole.length === 0 || !['Professeur', 'Coordinateur'].includes(senderRole[0].role)) {
                return res.status(403).json({ message: 'Seuls les professeurs ou coordinateurs peuvent envoyer des messages publics.' });
            }

            await connection.execute(
                'INSERT INTO Messages (sender_id, class_id, content, message_type) VALUES (?, ?, ?, ?)',
                [sender_id, class_id, content, message_type]
            );
            res.status(201).json({ message: 'Message public envoyé avec succès.' });
        }

    } catch (error) {
        console.error('Erreur lors de l\'envoi du message :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de l\'envoi du message.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir les messages publics d'une classe (accessible à tous les membres de la classe)
app.get('/api/messages/public/class/:classId', auth, async (req, res) => {
    const { classId } = req.params;
    const user_id = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        // Vérifier que l'utilisateur est membre de la classe
        const [isMember] = await connection.execute(
            'SELECT * FROM ClassMembers WHERE class_id = ? AND user_id = ?',
            [classId, user_id]
        );
        if (isMember.length === 0) {
            return res.status(403).json({ message: 'Accès non autorisé à cette classe.' });
        }

        const [messages] = await connection.execute(
            `SELECT M.id, M.content, M.created_at, U.prenom as senderPrenom, U.nom as senderNom, U.role as senderRole
             FROM Messages M
             JOIN Users U ON M.sender_id = U.id
             WHERE M.class_id = ? AND M.message_type = 'public'
             ORDER BY M.created_at DESC`,
            [classId]
        );
        res.status(200).json(messages);

    } catch (error) {
        console.error('Erreur lors de la récupération des messages publics :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération des messages publics.' });
    } finally {
        if (connection) connection.end();
    }
});

// Route pour obtenir les messages privés de l'utilisateur connecté
app.get('/api/messages/private/me', auth, async (req, res) => {
    const user_id = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        const [messages] = await connection.execute(
            `SELECT M.id, M.content, M.created_at, M.message_type,
                    S.prenom as senderPrenom, S.nom as senderNom, S.role as senderRole, S.id as senderId,
                    R.prenom as receiverPrenom, R.nom as receiverNom, R.role as receiverRole, R.id as receiverId
             FROM Messages M
             JOIN Users S ON M.sender_id = S.id
             LEFT JOIN Users R ON M.receiver_id = R.id -- LEFT JOIN car receiver_id peut être NULL pour les messages publics (bien que cette route soit pour les privés)
             WHERE (M.sender_id = ? OR M.receiver_id = ?) AND M.message_type = 'private'
             ORDER BY M.created_at DESC`,
            [user_id, user_id]
        );
        res.status(200).json(messages);

    } catch (error) {
        console.error('Erreur lors de la récupération des messages privés :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération des messages privés.' });
    } finally {
        if (connection) connection.end();
    }
});
app.get('/api/users/all', auth, authorizeRole(['Professeur', 'Coordinateur']), async (req, res) => {
    let connection;
    try {
        connection = await getConnection();
        const [users] = await connection.execute('SELECT id, prenom, nom, email, role FROM Users ORDER BY role, nom, prenom');
        res.status(200).json(users);
    } catch (error) {
        console.error('Erreur lors de la récupération de tous les utilisateurs :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur.' });
    } finally {
        if (connection) connection.end();
    }
});
app.get('/api/classes/me', auth, async (req, res) => {
    const user_id = req.user.id; // L'ID de l'utilisateur connecté

    let connection;
    try {
        connection = await getConnection();

        const [classes] = await connection.execute(
            `SELECT C.id, C.nom, C.description, C.code_acces
             FROM Classes C
             JOIN ClassMembers CM ON C.id = CM.class_id
             WHERE CM.user_id = ?
             ORDER BY C.nom`,
            [user_id]
        );
        res.status(200).json(classes);

    } catch (error) {
        console.error('Erreur lors de la récupération des classes de l\'utilisateur :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération de vos classes.' });
    } finally {
        if (connection) connection.end();
    }
});

// Créer un nouveau projet (accessible par Professeur ou Coordinateur)
app.post('/api/projects', auth, authorizeRole(['Professeur', 'Coordinateur']), async (req, res) => {
    const { class_id, titre, description, date_debut, date_fin } = req.body;
    const user_id = req.user.id; // L'utilisateur qui crée le projet

    let connection;
    try {
        connection = await getConnection();

        // Vérifier que l'utilisateur est bien Professeur/Coordinateur de cette classe
        const [isClassOwner] = await connection.execute(
            `SELECT * FROM Classes WHERE id = ? AND (professeur_id = ? OR EXISTS (SELECT 1 FROM Users WHERE id = ? AND role = 'Coordinateur'))`,
            [class_id, user_id, user_id]
        );
        if (isClassOwner.length === 0 && req.user.role !== 'Coordinateur') {
             return res.status(403).json({ message: 'Vous n\'avez pas la permission de créer un projet pour cette classe.' });
        }
        if (req.user.role === 'Coordinateur') { // Si coordinateur, vérifier qu'il est membre de la classe (s'il le faut)
             const [isMember] = await connection.execute(
                'SELECT * FROM ClassMembers WHERE class_id = ? AND user_id = ?',
                [class_id, user_id]
            );
            if (isMember.length === 0) {
                 return res.status(403).json({ message: 'En tant que Coordinateur, vous devez être membre de la classe pour créer un projet.' });
            }
        }


        const [result] = await connection.execute(
            'INSERT INTO Projets (class_id, titre, description, date_debut, date_fin) VALUES (?, ?, ?, ?, ?)',
            [class_id, titre, description, date_debut, date_fin]
        );
        res.status(201).json({ message: 'Projet créé avec succès.', projectId: result.insertId });

    } catch (error) {
        console.error('Erreur lors de la création du projet :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la création du projet.' });
    } finally {
        if (connection) connection.end();
    }
});

// Obtenir tous les projets d'une classe (accessible aux membres de la classe)
app.get('/api/projects/class/:classId', auth, async (req, res) => {
    const { classId } = req.params;
    const user_id = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        // Vérifier que l'utilisateur est membre de la classe
        const [isMember] = await connection.execute(
            'SELECT * FROM ClassMembers WHERE class_id = ? AND user_id = ?',
            [classId, user_id]
        );
        if (isMember.length === 0) {
            return res.status(403).json({ message: 'Accès non autorisé à cette classe.' });
        }

        const [projects] = await connection.execute(
            `SELECT id, class_id, titre, description, date_debut, date_fin, statut
             FROM Projets
             WHERE class_id = ?
             ORDER BY date_fin DESC`,
            [classId]
        );
        res.status(200).json(projects);

    } catch (error) {
        console.error('Erreur lors de la récupération des projets :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération des projets.' });
    } finally {
        if (connection) connection.end();
    }
});

app.post('/api/groups', auth, authorizeRole(['Professeur', 'Coordinateur']), async (req, res) => {
    const { projet_id, nom_groupe, description } = req.body;
    const user_id = req.user.id; // L'utilisateur qui crée le groupe

    let connection;
    try {
        connection = await getConnection();

        // Vérifier que le projet existe et que l'utilisateur a la permission d'y créer un groupe
        const [projectInfo] = await connection.execute(
            `SELECT P.class_id, C.professeur_id FROM Projets P JOIN Classes C ON P.class_id = C.id WHERE P.id = ?`,
            [projet_id]
        );

        if (projectInfo.length === 0) {
            return res.status(404).json({ message: 'Projet non trouvé.' });
        }

        const class_id = projectInfo[0].class_id;
        const professeur_id = projectInfo[0].professeur_id;

        // Si l'utilisateur n'est ni le professeur de la classe, ni un coordinateur, refuser
        if (professeur_id !== user_id && req.user.role !== 'Coordinateur') {
            return res.status(403).json({ message: 'Vous n\'avez pas la permission de créer un groupe pour ce projet.' });
        }
        // Si coordinateur, vérifier qu'il est membre de la classe du projet
        if (req.user.role === 'Coordinateur') {
             const [isMember] = await connection.execute(
                'SELECT * FROM ClassMembers WHERE class_id = ? AND user_id = ?',
                [class_id, user_id]
            );
            if (isMember.length === 0) {
                 return res.status(403).json({ message: 'En tant que Coordinateur, vous devez être membre de la classe du projet pour créer un groupe.' });
            }
        }


        const [result] = await connection.execute(
            'INSERT INTO Groupes (projet_id, nom_groupe, description) VALUES (?, ?, ?)',
            [projet_id, nom_groupe, description]
        );
        res.status(201).json({ message: 'Groupe créé avec succès.', groupId: result.insertId });

    } catch (error) {
        console.error('Erreur lors de la création du groupe :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la création du groupe.' });
    } finally {
        if (connection) connection.end();
    }
});

// Obtenir les groupes d'un projet spécifique, avec leurs membres
app.get('/api/groups/project/:projectId', auth, async (req, res) => {
    const { projectId } = req.params;
    const user_id = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        // Vérifier que le projet existe et que l'utilisateur est membre de la classe du projet
        const [projectClassInfo] = await connection.execute(
            `SELECT P.class_id FROM Projets P WHERE P.id = ?`,
            [projectId]
        );

        if (projectClassInfo.length === 0) {
            return res.status(404).json({ message: 'Projet non trouvé.' });
        }

        const class_id = projectClassInfo[0].class_id;
        const [isMember] = await connection.execute(
            'SELECT * FROM ClassMembers WHERE class_id = ? AND user_id = ?',
            [class_id, user_id]
        );
        if (isMember.length === 0) {
            return res.status(403).json({ message: 'Accès non autorisé à ce projet ou à sa classe.' });
        }

        // Récupérer les groupes
        const [groups] = await connection.execute(
            `SELECT G.id, G.nom_groupe, G.description
             FROM Groupes G
             WHERE G.projet_id = ?
             ORDER BY G.nom_groupe`,
            [projectId]
        );

        // Pour chaque groupe, récupérer ses membres
        for (let group of groups) {
            const [members] = await connection.execute(
                `SELECT U.id, U.prenom, U.nom, U.role
                 FROM MembresGroupe MG
                 JOIN Users U ON MG.user_id = U.id
                 WHERE MG.group_id = ?`,
                [group.id]
            );
            group.members = members;
        }

        res.status(200).json(groups);

    } catch (error) {
        console.error('Erreur lors de la récupération des groupes du projet :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération des groupes.' });
    } finally {
        if (connection) connection.end();
    }
});

// Ajouter un membre à un groupe (accessible par Professeur ou Coordinateur)
app.post('/api/groups/:groupId/members', auth, authorizeRole(['Professeur', 'Coordinateur']), async (req, res) => {
    const { groupId } = req.params;
    const { user_id_to_add } = req.body; // ID de l'utilisateur à ajouter
    const admin_user_id = req.user.id; // L'utilisateur qui ajoute le membre

    let connection;
    try {
        connection = await getConnection();

        // Vérifier que le groupe existe et que l'admin_user_id a la permission d'y ajouter un membre
        const [groupInfo] = await connection.execute(
            `SELECT G.projet_id, P.class_id, C.professeur_id
             FROM Groupes G
             JOIN Projets P ON G.projet_id = P.id
             JOIN Classes C ON P.class_id = C.id
             WHERE G.id = ?`,
            [groupId]
        );

        if (groupInfo.length === 0) {
            return res.status(404).json({ message: 'Groupe non trouvé.' });
        }

        const class_id = groupInfo[0].class_id;
        const professeur_id = groupInfo[0].professeur_id;

        // Si l'utilisateur n'est ni le professeur de la classe, ni un coordinateur, refuser
        if (professeur_id !== admin_user_id && req.user.role !== 'Coordinateur') {
            return res.status(403).json({ message: 'Vous n\'avez pas la permission de modifier ce groupe.' });
        }
        // Si coordinateur, vérifier qu'il est membre de la classe du projet du groupe
        if (req.user.role === 'Coordinateur') {
             const [isMember] = await connection.execute(
                'SELECT * FROM ClassMembers WHERE class_id = ? AND user_id = ?',
                [class_id, admin_user_id]
            );
            if (isMember.length === 0) {
                 return res.status(403).json({ message: 'En tant que Coordinateur, vous devez être membre de la classe du projet du groupe pour le modifier.' });
            }
        }


        // Vérifier que l'utilisateur à ajouter existe et est un étudiant
        const [userToAddInfo] = await connection.execute(
            'SELECT id, role FROM Users WHERE id = ?',
            [user_id_to_add]
        );
        if (userToAddInfo.length === 0 || userToAddInfo[0].role !== 'Etudiant') {
            return res.status(400).json({ message: 'L\'utilisateur à ajouter n\'existe pas ou n\'est pas un étudiant.' });
        }

        // Vérifier que l'étudiant est bien membre de la classe du projet
        const [isStudentInClass] = await connection.execute(
            'SELECT * FROM ClassMembers WHERE class_id = ? AND user_id = ?',
            [class_id, user_id_to_add]
        );
        if (isStudentInClass.length === 0) {
            return res.status(400).json({ message: 'L\'étudiant n\'est pas membre de la classe de ce projet.' });
        }

        // Vérifier si le membre n'est pas déjà dans le groupe
        const [existingMember] = await connection.execute(
            'SELECT * FROM MembresGroupe WHERE group_id = ? AND user_id = ?',
            [groupId, user_id_to_add]
        );
        if (existingMember.length > 0) {
            return res.status(409).json({ message: 'Cet utilisateur est déjà membre de ce groupe.' });
        }

        await connection.execute(
            'INSERT INTO MembresGroupe (group_id, user_id) VALUES (?, ?)',
            [groupId, user_id_to_add]
        );
        res.status(200).json({ message: 'Membre ajouté au groupe avec succès.' });

    } catch (error) {
        console.error('Erreur lors de l\'ajout d\'un membre au groupe :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de l\'ajout du membre.' });
    } finally {
        if (connection) connection.end();
    }
});

// Supprimer un membre d'un groupe (accessible par Professeur ou Coordinateur)
app.delete('/api/groups/:groupId/members/:userId', auth, authorizeRole(['Professeur', 'Coordinateur']), async (req, res) => {
    const { groupId, userId } = req.params;
    const admin_user_id = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        // Vérifier que le groupe existe et que l'admin_user_id a la permission de le modifier
        const [groupInfo] = await connection.execute(
            `SELECT G.projet_id, P.class_id, C.professeur_id
             FROM Groupes G
             JOIN Projets P ON G.projet_id = P.id
             JOIN Classes C ON P.class_id = C.id
             WHERE G.id = ?`,
            [groupId]
        );

        if (groupInfo.length === 0) {
            return res.status(404).json({ message: 'Groupe non trouvé.' });
        }

        const class_id = groupInfo[0].class_id;
        const professeur_id = groupInfo[0].professeur_id;

        if (professeur_id !== admin_user_id && req.user.role !== 'Coordinateur') {
            return res.status(403).json({ message: 'Vous n\'avez pas la permission de modifier ce groupe.' });
        }
        if (req.user.role === 'Coordinateur') {
             const [isMember] = await connection.execute(
                'SELECT * FROM ClassMembers WHERE class_id = ? AND user_id = ?',
                [class_id, admin_user_id]
            );
            if (isMember.length === 0) {
                 return res.status(403).json({ message: 'En tant que Coordinateur, vous devez être membre de la classe du projet du groupe pour le modifier.' });
            }
        }


        const [result] = await connection.execute(
            'DELETE FROM MembresGroupe WHERE group_id = ? AND user_id = ?',
            [groupId, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Membre non trouvé dans ce groupe.' });
        }

        res.status(200).json({ message: 'Membre supprimé du groupe avec succès.' });

    } catch (error) {
        console.error('Erreur lors de la suppression d\'un membre du groupe :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la suppression du membre.' });
    } finally {
        if (connection) connection.end();
    }
});

app.get('/api/classes/:classId/students', auth, async (req, res) => {
    const { classId } = req.params;
    const user_id = req.user.id;

    let connection;
    try {
        connection = await getConnection();

        // Vérifier que l'utilisateur est bien membre de cette classe
        const [isMember] = await connection.execute(
            'SELECT * FROM ClassMembers WHERE class_id = ? AND user_id = ?',
            [classId, user_id]
        );
        if (isMember.length === 0) {
            return res.status(403).json({ message: 'Accès non autorisé à cette classe.' });
        }

        const [students] = await connection.execute(
            `SELECT U.id, U.prenom, U.nom
             FROM Users U
             JOIN ClassMembers CM ON U.id = CM.user_id
             WHERE CM.class_id = ? AND U.role = 'Etudiant'
             ORDER BY U.prenom, U.nom`,
            [classId]
        );
        res.status(200).json(students);

    } catch (error) {
        console.error('Erreur lors de la récupération des étudiants de la classe :', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la récupération des étudiants de la classe.' });
    } finally {
        if (connection) connection.end();
    }
});

app.put('/api/users/:userId/role', auth, authorizeRole(['Coordinateur']), async (req, res) => {
    const { userId } = req.params;
    const { role } = req.body; // Nouveau rôle
    const requestingUserId = req.user.id; // ID de l'utilisateur qui fait la demande

    if (!role || !['Etudiant', 'Professeur', 'Coordinateur'].includes(role)) {
        return res.status(400).json({ message: 'Rôle invalide fourni.' });
    }

    // Empêcher un coordinateur de se rétrograder lui-même
    if (parseInt(userId) === requestingUserId && role !== 'Coordinateur') {
        return res.status(403).json({ message: 'Un Coordinateur ne peut pas se rétrograder lui-même.' });
    }

    let connection;
    try {
        connection = await getConnection();
        const [result] = await connection.execute(
            'UPDATE Users SET role = ? WHERE id = ?',
            [role, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Utilisateur non trouvé.' });
        }

        res.status(200).json({ message: `Rôle de l'utilisateur ${userId} mis à jour en "${role}".` });

    } catch (error) {
        console.error(`Erreur lors de la modification du rôle de l'utilisateur ${userId} :`, error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la modification du rôle.' });
    } finally {
        if (connection) connection.end();
    }
});

// Supprimer un utilisateur (accessible uniquement par un Coordinateur)
app.delete('/api/users/:userId', auth, authorizeRole(['Coordinateur']), async (req, res) => {
    const { userId } = req.params;
    const requestingUserId = req.user.id; // ID de l'utilisateur qui fait la demande

    // Empêcher un coordinateur de se supprimer lui-même
    if (parseInt(userId) === requestingUserId) {
        return res.status(403).json({ message: 'Un Coordinateur ne peut pas supprimer son propre compte.' });
    }

    let connection;
    try {
        connection = await getConnection();

        // Vérifier si l'utilisateur est le dernier coordinateur (empêcher la suppression du seul coordinateur)
        const [userToDelete] = await connection.execute('SELECT role FROM Users WHERE id = ?', [userId]);
        if (userToDelete.length > 0 && userToDelete[0].role === 'Coordinateur') {
            const [allCoordinators] = await connection.execute("SELECT COUNT(*) AS count FROM Users WHERE role = 'Coordinateur'");
            if (allCoordinators[0].count === 1) {
                return res.status(403).json({ message: 'Impossible de supprimer le seul compte Coordinateur.' });
            }
        }

        const [result] = await connection.execute(
            'DELETE FROM Users WHERE id = ?',
            [userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Utilisateur non trouvé.' });
        }

        res.status(200).json({ message: `Utilisateur ${userId} supprimé avec succès.` });

    } catch (error) {
        console.error(`Erreur lors de la suppression de l'utilisateur ${userId} :`, error.message);
        res.status(500).json({ message: 'Erreur interne du serveur lors de la suppression de l\'utilisateur.' });
    } finally {
        if (connection) connection.end();
    }
});

const checkIsGroupCoordinator = async (req, res, next) => {
    // Si req.user n'est pas défini, cela signifie que 'auth' n'a pas été exécuté,
    // donc l'utilisateur n'est pas authentifié.
    if (!req.user || !req.user.id) {
        return res.status(401).json({ message: 'Token non valide ou manquant.' });
    }

    const userId = req.user.id; // On récupère l'ID de l'utilisateur authentifié
    const { groupId } = req.params;

    let connection;
    try {
        connection = await getConnection();
        const [rows] = await connection.execute(
            'SELECT isGroupCoordinator FROM GroupMembers WHERE groupId = ? AND userId = ?',
            [groupId, userId]
        );
        
        if (rows.length > 0 && rows[0].isGroupCoordinator) {
            next(); // L'utilisateur est le responsable de ce groupe
        } else {
            res.status(403).json({ message: 'Accès refusé. Seul le responsable de ce groupe est autorisé.' });
        }
    } catch (error) {
        console.error('Erreur lors de la vérification du rôle de responsable de groupe:', error.message);
        res.status(500).json({ message: 'Erreur interne du serveur.' });
    } finally {
        if (connection) connection.end();
    }
};

module.exports = {
  checkIsGroupCoordinator
};


// Route de test simple pour vérifier que le serveur fonctionne (gardée)
app.get('/', (req, res) => {
    res.send('API React Classroom fonctionne correctement !');
});

// Démarrage du serveur
app.listen(port, () => {
    console.log(`🚀 Serveur backend démarré sur http://localhost:${port}`);
});