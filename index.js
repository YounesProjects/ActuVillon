const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const dotenv = require('dotenv');

// Charger les variables d'environnement
dotenv.config();

// Initialiser l'application Express
const app = express();
app.use(bodyParser.json());
app.use(cookieParser()); // Middleware pour gérer les cookies
app.set('view engine', 'ejs');
app.use(express.static('public')); // Servir les fichiers statiques (CSS, images, etc.)

// Se connecter à MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connecté'))
  .catch(err => console.error('Erreur de connexion à MongoDB :', err));

// Schéma Utilisateur
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  profilePicture: { type: String, default: '/images/default-avatar.png' }, // Avatar par défaut
  banner: { type: String, default: '/images/default-banner.png' }, // Bannière par défaut
  xp: { type: Number, default: 0 }, // Points d'expérience
  level: { type: Number, default: 1 }, // Niveau initial
  title: { type: String, default: '' }, // Titre attribué par l'admin
  nicknameColor: { type: String, default: '#000000' }, // Couleur du pseudo
});
const User = mongoose.model('User', userSchema);

// Schéma Article
const postSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true }, // Contenu HTML depuis l'éditeur de texte enrichi
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
  comments: [
    {
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      text: { type: String, required: true },
      createdAt: { type: Date, default: Date.now }
    }
  ]
});
const Post = mongoose.model('Post', postSchema);

// Middleware pour vérifier le token JWT dans les cookies
function verifyToken(req, res, next) {
  const token = req.cookies.token; // Récupérer le token des cookies
  if (!token) {
    console.log('Aucun token trouvé dans les cookies');
    return res.status(401).json({ message: 'Accès refusé' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    console.error('Erreur lors de la vérification du token :', err.message);
    res.status(400).json({ message: 'Token invalide' });
  }
}

// Routes

// Admin Panel Route
app.get('/admin', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user.isAdmin) return res.status(403).json({ message: 'Accès refusé. Réservé aux administrateurs.' });
    res.render('admin'); // Show the admin dashboard
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur.' });
  }
});

// Create Post Route
app.get('/create-post', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user.isAdmin) return res.status(403).json({ message: 'Accès refusé. Réservé aux administrateurs.' });
    res.render('create-post'); // Show the create post page
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur.' });
  }
});

// Update User Role Route
app.get('/update-user-role', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user.isAdmin) return res.status(403).json({ message: 'Accès refusé. Réservé aux administrateurs.' });
    res.render('update-user-role'); // Show the update user role page
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur.' });
  }
});

// Inscription d'un utilisateur
app.post('/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;

    // Vérifier si l'utilisateur existe déjà avec cet email ou ce nom d'utilisateur
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Cet email ou ce nom d\'utilisateur est déjà utilisé.' });
    }

    // Valider l'email (optionnel, mais recommandé)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Adresse email invalide.' });
    }

    // Hacher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // Créer un nouvel utilisateur
    const newUser = new User({
      email,
      username,
      password: hashedPassword,
      isAdmin: false
    });

    await newUser.save();

    // Répondre avec un message de succès
    res.json({ success: true, message: 'Inscription réussie !', redirect: '/' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// Page d'inscription
app.get('/register', (req, res) => {
  res.render('register'); // Afficher la page d'inscription
});

// Route de connexion
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Trouver l'utilisateur par son nom d'utilisateur
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ success: false, message: 'Identifiants invalides.' });

    // Valider le mot de passe
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: 'Identifiants invalides.' });

    // Générer un token JWT
    const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Définir le token comme cookie
    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });

    // Rediriger vers la page principale après 3 secondes
    res.json({ success: true, message: 'Connexion réussie !', redirect: '/' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// Page de connexion
app.get('/login', (req, res) => {
  res.render('login'); // Afficher la page de connexion
});

// Route de déconnexion
app.post('/logout', (req, res) => {
  res.clearCookie('token'); // Supprimer le cookie du token
  res.json({ success: true, message: 'Déconnexion réussie !' });
});

// Route du panneau d'administration
app.get('/admin', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user.isAdmin) {
      return res.json({ success: false, message: 'Accès refusé. Réservé aux administrateurs.' });
    }

    res.render('admin'); // Afficher la page d'administration
  } catch (err) {
    res.json({ success: false, message: 'Erreur serveur.' });
  }
});

// Créer un nouvel article
app.post('/posts', verifyToken, async (req, res) => {
  try {
    const { title, content } = req.body;

    // Créer un nouvel article
    const newPost = new Post({
      title,
      content,
      author: req.userId
    });
    await newPost.save();

    // Répondre avec un message de succès pour le pop-up
    res.json({ success: true, message: 'Article créé avec succès !' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'Erreur lors de la création de l\'article.' });
  }
});

// Get All Posts
app.get('/posts', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', 'username profilePicture')
      .sort({ createdAt: -1 });
    res.json(posts);
  } catch (err) {
    res.status(500).json({ message: 'Erreur lors de la récupération des articles.' });
  }
});

// Main Blog Page
app.get('/', async (req, res) => {
  const token = req.cookies.token; // Vérifier si un token est présent dans les cookies
  let user = null;

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET); // Vérifier le token
      user = await User.findById(decoded.id); // Trouver l'utilisateur dans la base de données
    } catch (err) {
      console.error('Token invalide :', err.message);
    }
  }

  // Récupérer tous les articles
  try {
    const posts = await Post.find()
      .populate('author', 'username profilePicture') // Remplir les informations de l'auteur
      .sort({ createdAt: -1 }); // Trier par date de création (les plus récents en premier)

    // Rendre la page du blog avec les articles et les informations de l'utilisateur
    res.render('blog', { user, posts });
  } catch (err) {
    console.error(err);
    res.render('blog', { user, posts: [] }); // Passer un tableau vide en cas d'erreur
  }
});

// Modifier un article
app.put('/posts/:id', verifyToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.json({ success: false, message: 'Article non trouvé.' });
    }

    // S'assurer que seul l'auteur peut modifier l'article
    if (post.author.toString() !== req.userId) {
      return res.json({ success: false, message: 'Accès refusé.' });
    }

    post.title = title;
    post.content = content;
    await post.save();

    res.json({ success: true, message: 'Article modifié avec succès !' });
  } catch (err) {
    res.json({ success: false, message: 'Erreur lors de la modification de l\'article.' });
  }
});

// Supprimer un article
app.delete('/posts/:id', verifyToken, async (req, res) => {
  try {
    const postId = req.params.id;
    console.log(`Tentative de suppression de l'article avec l'ID : ${postId}`);

    // Vérifier si le post existe
    const post = await Post.findById(postId);
    if (!post) {
      console.error('Article non trouvé.');
      return res.status(404).json({ success: false, message: 'Article non trouvé.' });
    }

    // Vérifier les permissions (seul l'auteur ou un administrateur peut supprimer)
    const user = await User.findById(req.userId);
    if (!user.isAdmin && post.author.toString() !== req.userId) {
      console.error('Accès refusé.');
      return res.status(403).json({ success: false, message: 'Accès refusé.' });
    }

    // Supprimer le post
    await Post.findByIdAndDelete(postId);
    console.log(`Article avec l'ID ${postId} supprimé avec succès.`);

    // Répondre avec un message de succès
    res.json({ success: true, message: 'Article supprimé avec succès !' });
  } catch (err) {
    console.error('Erreur lors de la suppression de l\'article :', err.message);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// Obtenir tous les articles
app.get('/posts', async (req, res) => {
  try {
    const posts = await Post.find().populate('author', 'username profilePicture').sort({ createdAt: -1 });
    res.json(posts);
  } catch (err) {
    res.json({ success: false, message: 'Erreur lors de la récupération des articles.' });
  }
});

// Obtenir un article par ID
app.get('/post/:id', async (req, res) => {
  try {
    const postId = req.params.id;

    // Trouver l'article par ID et remplir les champs de l'auteur
    const post = await Post.findById(postId)
      .populate('author', 'username profilePicture')
      .populate('comments.user', 'username profilePicture');
    if (!post) {
      return res.json({ success: false, message: 'Article non trouvé.' });
    }

    // Vérifier si l'utilisateur est connecté
    const token = req.cookies.token;
    let user = null;

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        user = await User.findById(decoded.id); // Trouver l'utilisateur connecté
      } catch (err) {
        console.error('Token invalide :', err.message);
      }
    }

    // Rendre la page de l'article avec les données de l'article et de l'utilisateur
    res.render('post', { post, user });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'Erreur serveur.' });
  }
});

// Ajouter un commentaire à un article
app.post('/posts/:id/comments', verifyToken, async (req, res) => {
  try {
    const { text } = req.body;
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: 'Post not found' });

    // Ajouter le commentaire
    post.comments.push({ user: req.userId, text });
    await post.save();

    // Augmenter l'XP de l'utilisateur
    const user = await User.findById(req.userId);
    user.xp += 10; // Exemple : +10 XP par commentaire
    if (user.xp >= 100 * user.level) {
      user.level += 1; // Monter de niveau si l'XP atteint le seuil
      user.xp = 0; // Réinitialiser l'XP après le passage de niveau
    }
    await user.save();

    res.json({ message: 'Comment added successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error adding comment' });
  }
});

// Page de personnalisation de l'utilisateur
app.get('/user', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.redirect('/login'); // Rediriger vers /login si l'utilisateur n'est pas trouvé

    res.render('user', { user });
  } catch (err) {
    console.error(err);
    res.redirect('/login'); // En cas d'erreur, rediriger également vers /login
  }
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/'); // Dossier où les fichiers sont sauvegardés
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname); // Nom unique pour chaque fichier
  }
});

const upload = multer({ storage: storage });

app.post('/user/update', verifyToken, upload.single('profilePicture'), async (req, res) => {
  try {
    const { nickname } = req.body;
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé.' });

    // Mettre à jour le pseudo
    if (nickname) {
      user.username = nickname;
    }

    // Mettre à jour la photo de profil si un fichier a été téléchargé
    if (req.file) {
      user.profilePicture = `/uploads/${req.file.filename}`;
    }

    await user.save();
    res.json({ message: 'Profil mis à jour avec succès.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Erreur lors de la mise à jour du profil.' });
  }
});

// Route pour mettre à jour le rôle d'un utilisateur (Admin Only)
app.put('/admin/users/:id', verifyToken, async (req, res) => {
  try {
    const { title } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'Utilisateur pas trouvé' });

    const admin = await User.findById(req.userId);
    if (!admin.isAdmin) return res.status(403).json({ message: 'Admins seulement.' });

    user.title = title;
    await user.save();

    res.json({ message: 'Titre ajouté !' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Erreur de serveur' });
  }
});

// Supprimer un article
app.delete('/posts/:id', verifyToken, async (req, res) => {
  try {
    const postId = req.params.id;
    const post = await Post.findById(postId);

    if (!post) return res.status(404).json({ success: false, message: 'Article non trouvé.' });

    // Vérifier si l'utilisateur connecté est l'auteur ou un administrateur
    const user = await User.findById(req.userId);
    if (!user.isAdmin && post.author.toString() !== req.userId) {
      return res.status(403).json({ success: false, message: 'Accès refusé.' });
    }

    // Supprimer l'article
    await post.remove();

    // Répondre avec un message de succès
    res.json({ success: true, message: 'Article supprimé avec succès !' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// Modifier un article
app.put('/posts/:id', verifyToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const post = await Post.findById(req.params.id);

    if (!post) return res.status(404).json({ success: false, message: 'Article non trouvé.' });

    // S'assurer que seul un administrateur peut modifier l'article
    const user = await User.findById(req.userId);
    if (!user.isAdmin) return res.status(403).json({ success: false, message: 'Accès refusé.' });

    post.title = title;
    post.content = content;
    await post.save();

    res.json({ success: true, message: 'Article mis à jour avec succès !' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Erreur lors de la mise à jour de l\'article.' });
  }
});

// Route GET pour la déconnexion
app.get('/logout', (req, res) => {
  res.clearCookie('token'); // Supprimer le cookie du token
  res.redirect('/'); // Rediriger vers la page d'accueil
});

// Démarrer le serveur
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Serveur en cours d'exécution sur le port ${PORT}`);
});

