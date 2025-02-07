const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
// On n'utilise plus multer pour le stockage local
const dotenv = require('dotenv');
const fileUpload = require('express-fileupload'); // Pour traiter les uploads de fichiers
const cloudinary = require('cloudinary').v2;

// Charger les variables d'environnement
dotenv.config();

// Configurer Cloudinary avec tes clés (à définir dans ton .env)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Initialiser l'application Express
const app = express();
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use(fileUpload()); // Middleware pour gérer les uploads de fichiers
app.set('view engine', 'ejs');

// Se connecter à MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connecté'))
  .catch(err => console.error('Erreur de connexion à MongoDB :', err));

// Schéma Utilisateur
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  profilePicture: { type: String, default: '/images/default-avatar.png' },
  banner: { type: String, default: '/images/default-banner.png' },
  xp: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  title: { type: String, default: '' },
  nicknameColor: { type: String, default: '#000000' },
  email: { type: String }
});
const User = mongoose.model('User', userSchema);

// Schéma Article
const postSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
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
  const token = req.cookies.token;
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

// -------------------------
// Déclaration des routes
// -------------------------

// Route pour l'inscription
app.post('/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Cet email ou ce nom d\'utilisateur est déjà utilisé.' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Adresse email invalide.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      email,
      username,
      password: hashedPassword,
      isAdmin: false
    });
    await newUser.save();
    res.json({ success: true, message: 'Inscription réussie !', redirect: '/' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// Pages d'inscription et de connexion
app.get('/register', (req, res) => res.render('register'));
app.get('/login', (req, res) => res.render('login'));

// Connexion
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ success: false, message: 'Identifiants invalides.' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: 'Identifiants invalides.' });
    const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
    res.json({ success: true, message: 'Connexion réussie !', redirect: '/' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// Déconnexion
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true, message: 'Déconnexion réussie !' });
});
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// Routes d'administration et de création d'articles (vérification du token incluse)
app.get('/admin', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user.isAdmin) return res.status(403).json({ message: 'Accès refusé. Réservé aux administrateurs.' });
    res.render('admin');
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur.' });
  }
});
app.get('/create-post', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user.isAdmin) return res.status(403).json({ message: 'Accès refusé. Réservé aux administrateurs.' });
    res.render('create-post');
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur.' });
  }
});
app.get('/update-user-role', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user.isAdmin) return res.status(403).json({ message: 'Accès refusé. Réservé aux administrateurs.' });
    res.render('update-user-role');
  } catch (err) {
    res.status(500).json({ message: 'Erreur serveur.' });
  }
});

// Création d'un article
app.post('/posts', verifyToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const newPost = new Post({
      title,
      content,
      author: req.userId
    });
    await newPost.save();
    res.json({ success: true, message: 'Article créé avec succès !' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'Erreur lors de la création de l\'article.' });
  }
});

// Récupération de tous les articles
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

// Page principale du blog
app.get('/', async (req, res) => {
  const token = req.cookies.token;
  let user = null;
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      user = await User.findById(decoded.id);
    } catch (err) {
      console.error('Token invalide :', err.message);
    }
  }
  try {
    const posts = await Post.find()
      .populate('author', 'username profilePicture')
      .sort({ createdAt: -1 });
    res.render('blog', { user, posts });
  } catch (err) {
    console.error(err);
    res.render('blog', { user, posts: [] });
  }
});

// Modification et suppression d'articles
app.put('/posts/:id', verifyToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ success: false, message: 'Article non trouvé.' });
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
app.delete('/posts/:id', verifyToken, async (req, res) => {
  try {
    const postId = req.params.id;
    console.log(`Tentative de suppression de l'article avec l'ID : ${postId}`);
    const post = await Post.findById(postId);
    if (!post) {
      console.error('Article non trouvé.');
      return res.status(404).json({ success: false, message: 'Article non trouvé.' });
    }
    const user = await User.findById(req.userId);
    if (!user.isAdmin && post.author.toString() !== req.userId) {
      console.error('Accès refusé.');
      return res.status(403).json({ success: false, message: 'Accès refusé.' });
    }
    await Post.findByIdAndDelete(postId);
    console.log(`Article avec l'ID ${postId} supprimé avec succès.`);
    res.json({ success: true, message: 'Article supprimé avec succès !' });
  } catch (err) {
    console.error('Erreur lors de la suppression de l\'article :', err.message);
    res.status(500).json({ success: false, message: 'Erreur serveur.' });
  }
});

// Obtenir un article par ID
app.get('/post/:id', async (req, res) => {
  try {
    const postId = req.params.id;
    const post = await Post.findById(postId)
      .populate('author', 'username profilePicture')
      .populate('comments.user', 'username profilePicture');
    if (!post) {
      return res.json({ success: false, message: 'Article non trouvé.' });
    }
    const token = req.cookies.token;
    let user = null;
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        user = await User.findById(decoded.id);
      } catch (err) {
        console.error('Token invalide :', err.message);
      }
    }
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
    post.comments.push({ user: req.userId, text });
    await post.save();
    const user = await User.findById(req.userId);
    user.xp += 10;
    if (user.xp >= 100 * user.level) {
      user.level += 1;
      user.xp = 0;
    }
    await user.save();
    res.json({ message: 'Commentaire ajouté !' });
  } catch (err) {
    res.status(500).json({ message: 'Erreur' });
  }
});

// Page de personnalisation de l'utilisateur
app.get('/user', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.redirect('/login');
    res.render('user', { user });
  } catch (err) {
    console.error(err);
    res.redirect('/login');
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

// -------------------------
// Route de mise à jour du profil utilisateur avec Cloudinary
// -------------------------
app.post('/user/update', verifyToken, async (req, res) => {
  try {
    const { nickname } = req.body;
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'Utilisateur non trouvé.' });
    
    // Mettre à jour le pseudo
    if (nickname) {
      user.username = nickname;
    }
    
    // Vérifier si un fichier a été envoyé via express-fileupload
    if (req.files && req.files.profilePicture) {
      const file = req.files.profilePicture;
      
      // Fonction pour uploader le fichier sur Cloudinary en utilisant un stream
      const streamUpload = (fileBuffer) => {
        return new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'profile_pictures' },
            (error, result) => {
              if (result) {
                resolve(result);
              } else {
                reject(error);
              }
            }
          );
          stream.end(fileBuffer);
        });
      };

      const result = await streamUpload(file.data);
      user.profilePicture = result.secure_url;
    }
    
    await user.save();
    res.json({ message: 'Profil mis à jour avec succès.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Erreur lors de la mise à jour du profil.' });
  }
});

// Démarrer le serveur
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Serveur en cours d'exécution sur le port ${PORT}`);
});
