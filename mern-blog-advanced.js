// create-mern-blog-advanced.js
import fs from "fs";
import path from "path";
import archiver from "archiver";

const projectName = "mern-blog-advanced";
const projectPath = path.join(process.cwd(), projectName);

function createDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function write(filePath, content) {
  fs.writeFileSync(filePath, content, { encoding: "utf8" });
}

// create folders
const folders = [
  "server",
  "server/config",
  "server/controllers",
  "server/models",
  "server/routes",
  "server/middleware",
  "server/data",
  "server/uploads",
  "client",
  "client/src",
  "client/src/pages",
  "client/src/components",
  "client/src/hooks",
  "client/src/context",
  "client/public",
];
folders.forEach((f) => createDir(path.join(projectPath, f)));

// --- SERVER FILES ---
const serverPackage = `{
  "name": "mern-blog-advanced-server",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "nodemon server.js",
    "start": "node server.js",
    "seed": "node data/seed.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "express-async-handler": "^1.2.0",
    "express-validator": "^7.0.1",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^7.5.0",
    "multer": "^1.4.5-lts.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}`;

write(path.join(projectPath, "server/package.json"), serverPackage);

write(path.join(projectPath, "server/.env.example"), `PORT=5000
MONGO_URI=mongodb://localhost:27017/mern_blog
JWT_SECRET=changeme
CLIENT_URL=http://localhost:5173
`);

// server/config/db.js
write(path.join(projectPath, "server/config/db.js"), `import mongoose from 'mongoose';

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB connected', conn.connection.host);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
};

export default connectDB;
`);

// server/models/User.js
write(path.join(projectPath, "server/models/User.js"), `import mongoose from 'mongoose';
const userSchema = mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}, { timestamps: true });

export default mongoose.model('User', userSchema);
`);

// server/models/Category.js
write(path.join(projectPath, "server/models/Category.js"), `import mongoose from 'mongoose';
const categorySchema = mongoose.Schema({
  name: { type: String, required: true, unique: true }
}, { timestamps: true });
export default mongoose.model('Category', categorySchema);
`);

// server/models/Post.js
write(path.join(projectPath, "server/models/Post.js"), `import mongoose from 'mongoose';
const commentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  body: String,
  createdAt: { type: Date, default: Date.now }
});

const postSchema = mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  image: String,
  comments: [commentSchema]
}, { timestamps: true });

export default mongoose.model('Post', postSchema);
`);

// server/middleware/errorHandler.js
write(path.join(projectPath, "server/middleware/errorHandler.js"), `const errorHandler = (err, req, res, next) => {
  const status = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(status).json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? null : err.stack
  });
};
export default errorHandler;
`);

// server/middleware/auth.js
write(path.join(projectPath, "server/middleware/auth.js"), `import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import User from '../models/User.js';

export const protect = asyncHandler(async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');
      next();
    } catch (err) {
      res.status(401);
      throw new Error('Not authorized, token failed');
    }
  }
  if (!token) {
    res.status(401);
    throw new Error('Not authorized, no token');
  }
});
`);

// server/controllers/authController.js
write(path.join(projectPath, "server/controllers/authController.js"), `import asyncHandler from 'express-async-handler';
import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const generateToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });

export const register = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;
  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(400);
    throw new Error('User already exists');
  }
  const salt = await bcrypt.genSalt(10);
  const hashed = await bcrypt.hash(password, salt);
  const user = await User.create({ name, email, password: hashed });
  res.status(201).json({ _id: user._id, name: user.name, email: user.email, token: generateToken(user._id) });
});

export const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && (await bcrypt.compare(password, user.password))) {
    res.json({ _id: user._id, name: user.name, email: user.email, token: generateToken(user._id) });
  } else {
    res.status(401);
    throw new Error('Invalid credentials');
  }
});
`);

// server/controllers/categoryController.js
write(path.join(projectPath, "server/controllers/categoryController.js"), `import asyncHandler from 'express-async-handler';
import Category from '../models/Category.js';

export const getCategories = asyncHandler(async (req, res) => {
  const categories = await Category.find({});
  res.json(categories);
});

export const createCategory = asyncHandler(async (req, res) => {
  const { name } = req.body;
  const exists = await Category.findOne({ name });
  if (exists) {
    res.status(400);
    throw new Error('Category exists');
  }
  const cat = await Category.create({ name });
  res.status(201).json(cat);
});
`);

// server/controllers/postController.js
write(path.join(projectPath, "server/controllers/postController.js"), `import asyncHandler from 'express-async-handler';
import Post from '../models/Post.js';
import Category from '../models/Category.js';

// GET /api/posts?search=&category=&page=&limit=
export const getPosts = asyncHandler(async (req, res) => {
  const page = Number(req.query.page) || 1;
  const limit = Number(req.query.limit) || 10;
  const search = req.query.search ? { title: { $regex: req.query.search, $options: 'i' } } : {};
  const categoryFilter = req.query.category ? { category: req.query.category } : {};

  const filter = { ...search, ...categoryFilter };

  const count = await Post.countDocuments(filter);
  const posts = await Post.find(filter)
    .populate('category')
    .populate('author', '-password')
    .sort({ createdAt: -1 })
    .skip(limit * (page - 1))
    .limit(limit);

  res.json({ posts, page, pages: Math.ceil(count / limit), total: count });
});

export const getPostById = asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id)
    .populate('category')
    .populate('author', '-password');
  if (!post) {
    res.status(404);
    throw new Error('Post not found');
  }
  res.json(post);
});

export const createPost = asyncHandler(async (req, res) => {
  const { title, content, category } = req.body;
  const post = await Post.create({
    title,
    content,
    category,
    author: req.user._id,
    image: req.file ? '/uploads/' + req.file.filename : undefined
  });
  res.status(201).json(post);
});

export const updatePost = asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) { res.status(404); throw new Error('Post not found'); }
  const { title, content, category } = req.body;
  post.title = title ?? post.title;
  post.content = content ?? post.content;
  post.category = category ?? post.category;
  if (req.file) post.image = '/uploads/' + req.file.filename;
  const updated = await post.save();
  res.json(updated);
});

export const deletePost = asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) { res.status(404); throw new Error('Post not found'); }
  await post.remove();
  res.json({ message: 'Post removed' });
});

export const addComment = asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) { res.status(404); throw new Error('Post not found'); }
  const comment = { user: req.user._id, body: req.body.body };
  post.comments.push(comment);
  await post.save();
  res.status(201).json(post);
});
`);

// server/routes/authRoutes.js
write(path.join(projectPath, "server/routes/authRoutes.js"), `import express from 'express';
import { register, login } from '../controllers/authController.js';
const router = express.Router();
router.post('/register', register);
router.post('/login', login);
export default router;
`);

// server/routes/categoryRoutes.js
write(path.join(projectPath, "server/routes/categoryRoutes.js"), `import express from 'express';
import { getCategories, createCategory } from '../controllers/categoryController.js';
import { protect } from '../middleware/auth.js';
const router = express.Router();
router.route('/').get(getCategories).post(protect, createCategory);
export default router;
`);

// server/routes/postRoutes.js
write(path.join(projectPath, "server/routes/postRoutes.js"), `import express from 'express';
import {
  getPosts, getPostById, createPost, updatePost, deletePost, addComment
} from '../controllers/postController.js';
import { protect } from '../middleware/auth.js';
import multer from 'multer';
const router = express.Router();

// multer setup
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, 'server/uploads/'); },
  filename: function (req, file, cb) { cb(null, Date.now() + '-' + file.originalname); }
});
const upload = multer({ storage });

router.route('/').get(getPosts).post(protect, upload.single('image'), createPost);
router.route('/:id').get(getPostById).put(protect, upload.single('image'), updatePost).delete(protect, deletePost);
router.route('/:id/comments').post(protect, addComment);

export default router;
`);

// server/server.js
write(path.join(projectPath, "server/server.js"), `import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import connectDB from './config/db.js';
import authRoutes from './routes/authRoutes.js';
import postRoutes from './routes/postRoutes.js';
import categoryRoutes from './routes/categoryRoutes.js';
import errorHandler from './middleware/errorHandler.js';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
connectDB();

const app = express();
app.use(cors({ origin: process.env.CLIENT_URL || '*' }));
app.use(express.json());
app.use('/uploads', express.static(path.join(path.resolve(), 'server/uploads')));

app.use('/api/auth', authRoutes);
app.use('/api/posts', postRoutes);
app.use('/api/categories', categoryRoutes);

app.use(errorHandler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(\`Server running on \${PORT}\`));
`);

// server/data/seed.js
write(path.join(projectPath, "server/data/seed.js"), `import mongoose from 'mongoose';
import dotenv from 'dotenv';
import connectDB from '../config/db.js';
import User from '../models/User.js';
import Category from '../models/Category.js';
import Post from '../models/Post.js';
import bcrypt from 'bcryptjs';

dotenv.config();
connectDB();

const seed = async () => {
  try {
    await User.deleteMany();
    await Category.deleteMany();
    await Post.deleteMany();

    const salt = await bcrypt.genSalt(10);
    const adminPassword = await bcrypt.hash('password', salt);

    const admin = await User.create({ name: 'Admin', email: 'admin@example.com', password: adminPassword });

    const cats = await Category.insertMany([
      { name: 'Technology' }, { name: 'Lifestyle' }, { name: 'Travel' }
    ]);

    const posts = [
      { title:'First Post', content:'Content for first post', category:cats[0]._id, author:admin._id },
      { title:'Second Post', content:'Second content', category:cats[1]._id, author:admin._id },
      { title:'Third Post', content:'Third content', category:cats[2]._id, author:admin._id }
    ];

    await Post.insertMany(posts);

    console.log('Seed complete');
    process.exit();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
};

seed();
`);

// --- CLIENT FILES ---
const clientPackage = `{
  "name": "mern-blog-advanced-client",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "axios": "^1.6.5",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.15.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.0.0",
    "vite": "^5.0.0"
  }
}`;
write(path.join(projectPath, "client/package.json"), clientPackage);

write(path.join(projectPath, "client/.env.example"), `VITE_API_URL=http://localhost:5000/api
VITE_CLIENT_URL=http://localhost:5173
`);

write(path.join(projectPath, "client/index.html"), `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1.0" />
    <title>MERN Blog Advanced</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
`);

// client/src/main.jsx
write(path.join(projectPath, "client/src/main.jsx"), `import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles.css';

createRoot(document.getElementById('root')).render(<App />);
`);

// client/src/App.jsx
write(path.join(projectPath, "client/src/App.jsx"), `import React from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import Home from './pages/Home';
import PostView from './pages/PostView';
import CreatePost from './pages/CreatePost';
import Login from './pages/Login';
import Register from './pages/Register';
import { AuthProvider } from './context/AuthContext';

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <nav className="nav">
          <Link to="/">Home</Link>
          <Link to="/create">Create</Link>
          <Link to="/login">Login</Link>
        </nav>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/posts/:id" element={<PostView />} />
          <Route path="/create" element={<CreatePost />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
`);

// client/src/styles.css
write(path.join(projectPath, "client/src/styles.css"), `body{font-family:Arial,Helvetica,sans-serif;margin:0;padding:0}
.nav{display:flex;gap:16px;padding:12px;background:#111;color:#fff}
.container{padding:16px}
.card{border:1px solid #ddd;padding:12px;margin-bottom:12px;border-radius:6px}
`);

// client/src/hooks/useApi.js
write(path.join(projectPath, "client/src/hooks/useApi.js"), `import { useState, useEffect } from 'react';
import axios from 'axios';

export default function useApi(url, opts = {}) {
  const [data, setData] = useState(opts.initial ?? null);
  const [loading, setLoading] = useState(Boolean(opts.auto ?? true));
  const [error, setError] = useState(null);

  useEffect(() => {
    if (opts.auto === false) return;
    let cancelled = false;
    const fetcher = async () => {
      setLoading(true);
      try {
        const res = await axios.get(url);
        if (!cancelled) setData(res.data);
      } catch (err) {
        if (!cancelled) setError(err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetcher();
    return () => (cancelled = true);
  }, [url]);

  return { data, loading, error, setData };
}
`);

// client/src/context/AuthContext.jsx
write(path.join(projectPath, "client/src/context/AuthContext.jsx"), `import React, { createContext, useState, useEffect } from 'react';
import axios from 'axios';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('user')); } catch { return null; }
  });

  useEffect(() => {
    localStorage.setItem('user', JSON.stringify(user));
  }, [user]);

  const login = async (email, password) => {
    const res = await axios.post(\`\${import.meta.env.VITE_API_URL}/auth/login\`, { email, password });
    setUser(res.data);
    return res.data;
  };
  const register = async (name, email, password) => {
    const res = await axios.post(\`\${import.meta.env.VITE_API_URL}/auth/register\`, { name, email, password });
    setUser(res.data);
    return res.data;
  };
  const logout = () => setUser(null);

  return <AuthContext.Provider value={{ user, login, register, logout }}>{children}</AuthContext.Provider>;
};

export default AuthContext;
`);

// client/src/pages/Home.jsx
write(path.join(projectPath, "client/src/pages/Home.jsx"), `import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

export default function Home(){
  const [posts, setPosts] = useState([]);
  const [q, setQ] = useState('');
  const [page, setPage] = useState(1);
  const limit = 6;

  useEffect(()=>{ fetchPosts(); }, [q, page]);

  const fetchPosts = async ()=>{
    const res = await axios.get(\`\${import.meta.env.VITE_API_URL}/posts?search=\${encodeURIComponent(q)}&page=\${page}&limit=\${limit}\`);
    setPosts(res.data.posts);
  };

  return (
    <div className="container">
      <h1>Blog</h1>
      <input placeholder="Search..." value={q} onChange={(e)=>setQ(e.target.value)} />
      {posts.map(p => (
        <div key={p._id} className="card">
          <h3><Link to={'/posts/'+p._id}>{p.title}</Link></h3>
          <p>{p.content.substring(0,150)}...</p>
        </div>
      ))}
      <div style={{display:'flex',gap:8}}>
        <button onClick={()=>setPage(p=>Math.max(1,p-1))}>Prev</button>
        <button onClick={()=>setPage(p=>p+1)}>Next</button>
      </div>
    </div>
  );
}
`);

// client/src/pages/PostView.jsx
write(path.join(projectPath, "client/src/pages/PostView.jsx"), `import React, { useEffect, useState, useContext } from 'react';
import axios from 'axios';
import { useParams } from 'react-router-dom';
import AuthContext from '../context/AuthContext';

export default function PostView(){
  const { id } = useParams();
  const [post, setPost] = useState(null);
  const [body, setBody] = useState('');
  const { user } = useContext(AuthContext);

  useEffect(()=>{ fetch(); }, [id]);

  const fetch = async ()=> {
    const res = await axios.get(\`\${import.meta.env.VITE_API_URL}/posts/\${id}\`);
    setPost(res.data);
  };

  const addComment = async () => {
    if(!user) return alert('Login to comment');
    await axios.post(\`\${import.meta.env.VITE_API_URL}/posts/\${id}/comments\`, { body }, { headers: { Authorization: 'Bearer ' + user.token }});
    setBody('');
    fetch(); // simple refresh — could be optimistic
  };

  if(!post) return <div className="container">Loading...</div>;

  return (
    <div className="container">
      <h1>{post.title}</h1>
      {post.image && <img src={import.meta.env.VITE_API_URL.replace('/api','') + post.image} alt="" style={{maxWidth:400}} />}
      <p>{post.content}</p>
      <h3>Comments</h3>
      {post.comments?.map(c => <div key={c._id} className="card"><p>{c.body}</p></div>)}
      <textarea value={body} onChange={e=>setBody(e.target.value)} placeholder="Write a comment" />
      <button onClick={addComment}>Comment</button>
    </div>
  );
}
`);

// client/src/pages/CreatePost.jsx
write(path.join(projectPath, "client/src/pages/CreatePost.jsx"), `import React, { useState, useContext } from 'react';
import axios from 'axios';
import AuthContext from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';

export default function CreatePost(){
  const { user } = useContext(AuthContext);
  const nav = useNavigate();
  const [title,setTitle] = useState('');
  const [content,setContent] = useState('');
  const [category,setCategory] = useState('');
  const [image,setImage] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    if(!user) return alert('Login first');
    const form = new FormData();
    form.append('title', title);
    form.append('content', content);
    form.append('category', category);
    if(image) form.append('image', image);
    await axios.post(\`\${import.meta.env.VITE_API_URL}/posts\`, form, { headers: { Authorization: 'Bearer ' + user.token, 'Content-Type': 'multipart/form-data' }});
    nav('/');
  };

  return (
    <div className="container">
      <h1>Create Post</h1>
      <form onSubmit={submit}>
        <input value={title} onChange={e=>setTitle(e.target.value)} placeholder="Title" required />
        <textarea value={content} onChange={e=>setContent(e.target.value)} placeholder="Content" required />
        <input value={category} onChange={e=>setCategory(e.target.value)} placeholder="Category" />
        <input type="file" onChange={e=>setImage(e.target.files[0])} />
        <button type="submit">Create</button>
      </form>
    </div>
  );
}
`);

// client/src/pages/Login.jsx
write(path.join(projectPath, "client/src/pages/Login.jsx"), `import React, { useState, useContext } from 'react';
import AuthContext from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';

export default function Login(){
  const [email,setEmail] = useState('');
  const [password,setPassword] = useState('');
  const { login } = useContext(AuthContext);
  const nav = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    try {
      await login(email, password);
      nav('/');
    } catch (err) { alert('Login failed'); }
  };

  return (
    <div className="container">
      <h1>Login</h1>
      <form onSubmit={submit}>
        <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="Email" />
        <input value={password} onChange={e=>setPassword(e.target.value)} placeholder="Password" type="password" />
        <button type="submit">Login</button>
      </form>
    </div>
  );
}
`);

// client/src/pages/Register.jsx
write(path.join(projectPath, "client/src/pages/Register.jsx"), `import React, { useState, useContext } from 'react';
import AuthContext from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';

export default function Register(){
  const [name,setName] = useState('');
  const [email,setEmail] = useState('');
  const [password,setPassword] = useState('');
  const { register } = useContext(require('../context/AuthContext').default);
  const nav = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    try {
      await register(name, email, password);
      nav('/');
    } catch (err) { alert('Register failed'); }
  };

  return (
    <div className="container">
      <h1>Register</h1>
      <form onSubmit={submit}>
        <input value={name} onChange={e=>setName(e.target.value)} placeholder="Name" />
        <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="Email" />
        <input value={password} onChange={e=>setPassword(e.target.value)} placeholder="Password" type="password" />
        <button type="submit">Register</button>
      </form>
    </div>
  );
}
`);

// client/README
write(path.join(projectPath, "client/README.md"), `Client Quickstart
1. cd client
2. npm install
3. cp .env.example .env
4. npm run dev
`);

// server README and root README
write(path.join(projectPath, "server/README.md"), `Server Quickstart
1. cd server
2. npm install
3. cp .env.example .env
4. npm run seed
5. npm run dev
`);

write(path.join(projectPath, "README.md"), `MERN Blog Advanced - Starter
This project was created by a script. It includes:
- server: Express, Mongoose, JWT Auth, Multer image uploads, validation, comments, pagination, search
- client: React + Vite, pages for listing, viewing, creating posts, auth
Run server and client individually as described in their READMEs.
`);

// create gitignore files
write(path.join(projectPath, "server/.gitignore"), `node_modules
.env
uploads
`);
write(path.join(projectPath, "client/.gitignore"), `node_modules
.env
dist
`);

// create zip
const zipPath = path.join(process.cwd(), projectName + ".zip");
const output = fs.createWriteStream(zipPath);
const archive = archiver("zip", { zlib: { level: 9 } });

output.on("close", () => {
  console.log("Created zip:", zipPath, archive.pointer() + " bytes");
});
archive.pipe(output);
archive.directory(projectPath, false);
archive.finalize();

console.log("Project generated at:", projectPath);
console.log("Zipping... Please wait.");
