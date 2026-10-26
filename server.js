require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "uploads");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "fredrick-movies.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS movies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  category TEXT DEFAULT 'Other',
  poster_url TEXT DEFAULT '',
  video_url TEXT NOT NULL,
  source_type TEXT NOT NULL DEFAULT 'embed',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  starts_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  payment_ref TEXT NOT NULL UNIQUE,
  amount_ugx INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  tx_ref TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending',
  amount_ugx INTEGER NOT NULL,
  provider_transaction_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

const adminEmail = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || "";
if (adminEmail && adminPassword && !db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail)) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users(name,email,password_hash,is_admin) VALUES(?,?,?,1)")
    .run("Administrator", adminEmail, hash);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(express.json({ limit: "2mb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || "development-only-change-this",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use("/uploads", express.static(UPLOAD_DIR));
app.use(express.static(path.join(ROOT, "public")));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase().slice(0, 10);
      cb(null, `${Date.now()}-${crypto.randomBytes(5).toString("hex")}${ext}`);
    }
  }),
  limits: { fileSize: 1024 * 1024 * 500 },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype.startsWith("video/")) return cb(new Error("Please upload a video file."));
    cb(null, true);
  }
});

const price = () => Math.max(1, Number.parseInt(process.env.SUBSCRIPTION_PRICE_UGX || "500", 10));
const days = () => Math.max(1, Number.parseInt(process.env.SUBSCRIPTION_DAYS || "30", 10));
const contactPhone = process.env.CONTACT_PHONE || "0700975576";
const money = n => `UGX ${Number(n).toLocaleString("en-UG")}`;

function activeSubscription(userId) {
  return db.prepare("SELECT * FROM subscriptions WHERE user_id=? AND expires_at > ? ORDER BY expires_at DESC LIMIT 1")
    .get(userId, new Date().toISOString());
}
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login?next=" + encodeURIComponent(req.originalUrl));
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) return res.status(403).send(page("Access denied", `<section class="panel"><h1>Admin only</h1><p>Sign in with the administrator account configured in your .env file.</p><a class="btn" href="/login">Sign in</a></section>`));
  next();
}
function page(title, body) {
  const user = null;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} | FREDRICK MOVIES</title><link rel="stylesheet" href="/style.css"></head><body>
  <header class="topbar"><a class="brand" href="/">🎬 FREDRICK <span>MOVIES</span></a><nav><a href="/">Home</a><a href="/movies">Movies</a>${userNav()}</nav></header>
  <main class="container">${body}</main><footer><p>© ${new Date().getFullYear()} FREDRICK MOVIES · Stream responsibly.</p><p>Contact: ${escapeHtml(contactPhone)}</p></footer></body></html>`;
}
function userNav() {
  return `<a href="/account">My account</a>${`<a href="/subscribe">Subscribe</a>`}${`<a href="/admin">Admin</a>`}`;
}
function escapeHtml(v="") {
  return String(v).replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
}
function flash(req) {
  const msg = req.session.flash;
  delete req.session.flash;
  return msg ? `<div class="notice">${escapeHtml(msg)}</div>` : "";
}
function currentUser(req) { return req.session.user || null; }
function movieCard(m, unlocked) {
  const poster = m.poster_url ? `<img src="${escapeHtml(m.poster_url)}" alt="">` : `<div class="poster-placeholder">🎬</div>`;
  return `<article class="movie-card"><a href="/movie/${m.id}">${poster}<div class="movie-info"><span class="tag">${escapeHtml(m.category)}</span><h3>${escapeHtml(m.title)}</h3><p>${escapeHtml((m.description||"").slice(0,100))}</p><span class="watch">${unlocked ? "Watch movie →" : "View movie →"}</span></div></a></article>`;
}
function isValidHttpUrl(s) {
  try { const u = new URL(s); return u.protocol === "https:" || u.protocol === "http:"; } catch { return false; }
}
function safeEmbedUrl(raw) {
  try {
    const u = new URL(raw);
    if (u.hostname === "youtu.be") return `https://www.youtube-nocookie.com/embed/${u.pathname.slice(1)}`;
    if (u.hostname.endsWith("youtube.com") && u.pathname === "/watch") return `https://www.youtube-nocookie.com/embed/${u.searchParams.get("v")}`;
    if (u.hostname.endsWith("youtube.com") && u.pathname.startsWith("/embed/")) return raw;
    if (u.hostname.endsWith("vimeo.com")) {
      const id = u.pathname.split("/").filter(Boolean).pop();
      if (/^\d+$/.test(id || "")) return `https://player.vimeo.com/video/${id}`;
    }
    return raw;
  } catch { return ""; }
}

app.get("/", (req, res) => {
  const movies = db.prepare("SELECT * FROM movies ORDER BY id DESC LIMIT 8").all();
  const active = currentUser(req) && activeSubscription(req.session.user.id);
  res.send(page("Home", `${flash(req)}
    <section class="hero"><div><p class="eyebrow">YOUR MOVIE NIGHT STARTS HERE</p><h1>Stories worth<br><span>staying up for.</span></h1><p>Discover action, comedy, horror, romance and more on FREDRICK MOVIES.</p><div class="actions"><a class="btn" href="/movies">Explore movies</a><a class="btn btn-outline" href="/subscribe">30-day access · ${money(price())}</a></div></div><div class="hero-art"><div class="film-reel">▶</div><div class="floating f1">ACTION</div><div class="floating f2">HORROR</div><div class="floating f3">DRAMA</div></div></section>
    <section class="section-heading"><div><p class="eyebrow">HAND-PICKED FOR YOU</p><h2>Latest movies</h2></div><a href="/movies">View all →</a></section>
    <section class="movie-grid">${movies.length ? movies.map(m=>movieCard(m,!!active)).join("") : `<div class="empty"><div>🎞️</div><h3>No movies yet</h3><p>Sign in as the administrator and add your first movie.</p></div>`}</section>
    <section class="subscribe-banner"><div><p class="eyebrow">ONE SMALL SUBSCRIPTION</p><h2>Enjoy 30 days of movie access</h2><p>Subscribe once, then watch the available catalogue while your access is active.</p></div><a class="btn" href="/subscribe">Get access · ${money(price())}</a></section>`));
});

app.get("/movies", (req, res) => {
  const q = (req.query.q || "").toString().trim();
  const category = (req.query.category || "").toString().trim();
  const movies = db.prepare(`SELECT * FROM movies WHERE (?='' OR title LIKE ? OR description LIKE ?) AND (?='' OR category=?) ORDER BY id DESC`)
    .all(q, `%${q}%`, `%${q}%`, category, category);
  const cats = db.prepare("SELECT DISTINCT category FROM movies ORDER BY category").all().map(x=>x.category);
  const active = currentUser(req) && activeSubscription(req.session.user.id);
  res.send(page("Movies", `${flash(req)}<section class="page-heading"><p class="eyebrow">THE COLLECTION</p><h1>Find your next favourite.</h1><p>Search the catalogue and choose what to watch.</p></section>
  <form class="filters" action="/movies"><input name="q" value="${escapeHtml(q)}" placeholder="Search movies..."><select name="category"><option value="">All categories</option>${cats.map(c=>`<option ${c===category?"selected":""}>${escapeHtml(c)}</option>`).join("")}</select><button class="btn">Search</button></form>
  <section class="movie-grid">${movies.length ? movies.map(m=>movieCard(m,!!active)).join("") : `<div class="empty"><div>🔎</div><h3>No movies found</h3><p>Try another search or category.</p></div>`}</section>`));
});

app.get("/movie/:id", (req, res) => {
  const m = db.prepare("SELECT * FROM movies WHERE id=?").get(Number(req.params.id));
  if (!m) return res.status(404).send(page("Not found", `<section class="panel"><h1>Movie not found</h1><a href="/movies">Back to movies</a></section>`));
  const user = currentUser(req);
  const active = user && activeSubscription(user.id);
  let watchArea;
  if (!active) {
    watchArea = `<div class="locked"><div class="lock-icon">🔒</div><h2>This movie is for subscribers</h2><p>Get 30 days of access to the available catalogue for <strong>${money(price())}</strong>.</p><a class="btn" href="/subscribe">Unlock movie access</a></div>`;
  } else {
    const video = m.source_type === "upload"
      ? `<video controls playsinline preload="metadata" src="${escapeHtml(m.video_url)}"></video>`
      : `<iframe src="${escapeHtml(safeEmbedUrl(m.video_url))}" title="${escapeHtml(m.title)}" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe>`;
    watchArea = `<div class="video-frame">${video}</div><p class="muted">Only watch content you have permission to stream. Some third-party sites may block embedding.</p>`;
  }
  const poster = m.poster_url ? `<img class="detail-poster" src="${escapeHtml(m.poster_url)}" alt="">` : "";
  res.send(page(m.title, `<a class="back-link" href="/movies">← All movies</a><section class="movie-detail">${poster}<div><span class="tag">${escapeHtml(m.category)}</span><h1>${escapeHtml(m.title)}</h1><p>${escapeHtml(m.description)}</p>${watchArea}</div></section>`));
});

app.get("/register", (req,res)=>res.send(page("Create account", `${flash(req)}<section class="form-card"><p class="eyebrow">JOIN THE COMMUNITY</p><h1>Create your account</h1><form method="post" action="/register"><label>Full name<input name="name" required maxlength="80"></label><label>Email address<input name="email" type="email" required maxlength="180"></label><label>Password<input name="password" type="password" minlength="8" required></label><button class="btn full">Create account</button></form><p>Already registered? <a href="/login">Sign in</a></p></section>`)));
app.post("/register", async (req,res)=>{
  const name=(req.body.name||"").trim(), email=(req.body.email||"").trim().toLowerCase(), password=req.body.password||"";
  if (!name || !email || password.length<8) { req.session.flash="Enter your name, valid email and a password of at least 8 characters."; return res.redirect("/register"); }
  try {
    const hash=await bcrypt.hash(password,12);
    const result=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name,email,hash);
    req.session.user={id:Number(result.lastInsertRowid),name,email,is_admin:0};
    res.redirect("/account");
  } catch { req.session.flash="That email may already be registered. Please sign in."; res.redirect("/register"); }
});
app.get("/login", (req,res)=>res.send(page("Sign in", `${flash(req)}<section class="form-card"><p class="eyebrow">WELCOME BACK</p><h1>Sign in</h1><form method="post" action="/login"><label>Email address<input name="email" type="email" required></label><label>Password<input name="password" type="password" required></label><button class="btn full">Sign in</button></form><p>New here? <a href="/register">Create an account</a></p></section>`)));
app.post("/login", async (req,res)=>{
  const email=(req.body.email||"").trim().toLowerCase(), password=req.body.password||"";
  const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!u || !(await bcrypt.compare(password,u.password_hash))) { req.session.flash="Email or password is incorrect."; return res.redirect("/login"); }
  req.session.user={id:u.id,name:u.name,email:u.email,is_admin:u.is_admin};
  res.redirect(u.is_admin?"/admin":"/account");
});
app.post("/logout",(req,res)=>req.session.destroy(()=>res.redirect("/")));

app.get("/account", requireLogin, (req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE id=?").get(req.session.user.id);
  const sub=activeSubscription(u.id);
  const past=db.prepare("SELECT * FROM subscriptions WHERE user_id=? ORDER BY id DESC LIMIT 5").all(u.id);
  res.send(page("My account", `${flash(req)}<section class="page-heading"><p class="eyebrow">YOUR SPACE</p><h1>Hello, ${escapeHtml(u.name)}.</h1><p>Manage your account and subscription.</p></section><div class="account-grid"><section class="panel"><h2>Subscription status</h2>${sub?`<span class="status active">Active</span><p>Access expires: <strong>${new Date(sub.expires_at).toLocaleString()}</strong></p>`:`<span class="status inactive">Not active</span><p>Subscribe to unlock the movie catalogue.</p><a class="btn" href="/subscribe">Subscribe · ${money(price())}</a>`}</section><section class="panel"><h2>Account details</h2><p><strong>Name:</strong> ${escapeHtml(u.name)}</p><p><strong>Email:</strong> ${escapeHtml(u.email)}</p><form method="post" action="/logout"><button class="btn btn-outline">Sign out</button></form></section></div><section class="panel"><h2>Recent subscriptions</h2>${past.length?`<div class="table-wrap"><table><tr><th>Started</th><th>Expires</th><th>Amount</th></tr>${past.map(s=>`<tr><td>${new Date(s.starts_at).toLocaleDateString()}</td><td>${new Date(s.expires_at).toLocaleDateString()}</td><td>${money(s.amount_ugx)}</td></tr>`).join("")}</table></div>`:`<p class="muted">No subscription history yet.</p>`}</section>`));
});

app.get("/subscribe", requireLogin, (req,res)=>{
  const sub=activeSubscription(req.session.user.id);
  res.send(page("Subscribe", `${flash(req)}<section class="pricing-card"><p class="eyebrow">FREDRICK MOVIES PASS</p><div class="price">${money(price())}<small> / 30 days</small></div><h1>One pass. A whole catalogue.</h1><p>Watch available movies while your subscription is active. Your subscription starts only after the payment is verified.</p>${sub?`<div class="notice">Your current access is active until ${new Date(sub.expires_at).toLocaleDateString()}.</div>`:""}<ul class="check-list"><li>✓ Access to the available movie catalogue</li><li>✓ Mobile-friendly streaming pages</li><li>✓ Renew when your access expires</li></ul><form method="post" action="/pay"><button class="btn full" ${!process.env.FLW_SECRET_KEY?"disabled title='Payment provider is not configured yet'":""}>Pay securely with mobile money</button></form>${!process.env.FLW_SECRET_KEY?`<p class="muted small">Online payments are not activated yet. The site owner must configure approved Flutterwave credentials in the deployment settings.</p>`:""}<p class="muted small">Price is charged in UGX. Payment methods depend on provider availability and account approval.</p></section>`));
});

app.post("/pay", requireLogin, async (req,res)=>{
  if (!process.env.FLW_SECRET_KEY) { req.session.flash="Payments are not configured yet. Please contact the site administrator."; return res.redirect("/subscribe"); }
  const user=db.prepare("SELECT * FROM users WHERE id=?").get(req.session.user.id);
  const tx_ref=`FM-${Date.now()}-${crypto.randomBytes(5).toString("hex")}`;
  const amount=price();
  db.prepare("INSERT INTO payments(user_id,tx_ref,status,amount_ugx) VALUES(?,?,?,?)").run(user.id,tx_ref,"pending",amount);
  try {
    const response=await fetch("https://api.flutterwave.com/v3/payments",{
      method:"POST",
      headers:{"Authorization":`Bearer ${process.env.FLW_SECRET_KEY}`,"Content-Type":"application/json"},
      body:JSON.stringify({
        tx_ref, amount, currency:"UGX",
        redirect_url:`${process.env.BASE_URL || `http://localhost:${PORT}`}/payment/callback`,
        payment_options:"mobilemoneyuganda",
        customer:{email:user.email,name:user.name},
        customizations:{title:"FREDRICK MOVIES",description:`${days()} days movie subscription`,logo:""}
      })
    });
    const data=await response.json();
    if (data.status==="success" && data.data && data.data.link) return res.redirect(data.data.link);
    console.error("Flutterwave checkout error", data);
    req.session.flash="Could not start payment. Check payment provider settings and try again.";
    res.redirect("/subscribe");
  } catch(e) {
    console.error(e);
    req.session.flash="Payment service is temporarily unavailable. Please try again later.";
    res.redirect("/subscribe");
  }
});

app.get("/payment/callback", requireLogin, async (req,res)=>{
  const transactionId=req.query.transaction_id;
  const txRef=req.query.tx_ref;
  if (!transactionId || !txRef) { req.session.flash="Payment was not confirmed. If money was deducted, contact support."; return res.redirect("/account"); }
  try {
    const response=await fetch(`https://api.flutterwave.com/v3/transactions/${encodeURIComponent(transactionId)}/verify`,{
      headers:{"Authorization":`Bearer ${process.env.FLW_SECRET_KEY}`}
    });
    const result=await response.json();
    const data=result.data;
    const payment=db.prepare("SELECT * FROM payments WHERE tx_ref=? AND user_id=?").get(txRef,req.session.user.id);
    const valid=payment && result.status==="success" && data &&
      data.status==="successful" &&
      String(data.tx_ref)===String(txRef) &&
      String(data.currency)==="UGX" &&
      Number(data.amount)>=Number(payment.amount_ugx);
    if (!valid) {
      if (payment) db.prepare("UPDATE payments SET status='failed', provider_transaction_id=? WHERE tx_ref=?").run(String(transactionId),txRef);
      req.session.flash="Payment could not be verified. If you were charged, contact support before trying again.";
      return res.redirect("/account");
    }
    const already=db.prepare("SELECT id FROM subscriptions WHERE payment_ref=?").get(txRef);
    if (!already) {
      const now=new Date();
      const current=activeSubscription(req.session.user.id);
      const start=current && new Date(current.expires_at)>now ? new Date(current.expires_at) : now;
      const expiry=new Date(start.getTime()+days()*24*60*60*1000);
      db.prepare("INSERT INTO subscriptions(user_id,starts_at,expires_at,payment_ref,amount_ugx) VALUES(?,?,?,?,?)")
        .run(req.session.user.id,start.toISOString(),expiry.toISOString(),txRef,payment.amount_ugx);
      db.prepare("UPDATE payments SET status='successful', provider_transaction_id=? WHERE tx_ref=?").run(String(transactionId),txRef);
    }
    req.session.flash="Payment verified! Your movie subscription is active.";
    res.redirect("/account");
  } catch(e) {
    console.error(e);
    req.session.flash="We could not verify the payment right now. Check your account or contact support.";
    res.redirect("/account");
  }
});

app.get("/admin", requireAdmin, (req,res)=>{
  const movies=db.prepare("SELECT * FROM movies ORDER BY id DESC").all();
  const users=db.prepare("SELECT u.id,u.name,u.email,u.created_at, s.expires_at FROM users u LEFT JOIN subscriptions s ON s.id=(SELECT id FROM subscriptions WHERE user_id=u.id ORDER BY expires_at DESC LIMIT 1) ORDER BY u.id DESC LIMIT 100").all();
  const stats={
    movies:db.prepare("SELECT COUNT(*) n FROM movies").get().n,
    users:db.prepare("SELECT COUNT(*) n FROM users WHERE is_admin=0").get().n,
    active:db.prepare("SELECT COUNT(DISTINCT user_id) n FROM subscriptions WHERE expires_at>?").get(new Date().toISOString()).n,
    payments:db.prepare("SELECT COUNT(*) n FROM payments WHERE status='successful'").get().n
  };
  res.send(page("Admin dashboard", `${flash(req)}<section class="page-heading"><p class="eyebrow">CONTROL ROOM</p><h1>Admin dashboard</h1><p>Add movies, manage the catalogue and check subscription activity.</p></section>
  <div class="stats"><div><strong>${stats.movies}</strong><span>Movies</span></div><div><strong>${stats.users}</strong><span>Members</span></div><div><strong>${stats.active}</strong><span>Active subscriptions</span></div><div><strong>${stats.payments}</strong><span>Successful payments</span></div></div>
  <section class="panel"><h2>Add a movie</h2><form class="admin-form" method="post" action="/admin/movies" enctype="multipart/form-data"><label>Movie title<input name="title" required maxlength="180"></label><label>Category<select name="category">${["Action","Comedy","Horror","Romance","Drama","Documentary","Animation","Other"].map(c=>`<option>${c}</option>`).join("")}</select></label><label>Description<textarea name="description" rows="3" maxlength="1500"></textarea></label><label>Poster image URL (optional)<input name="poster_url" type="url" placeholder="https://..."></label><label>Video link (YouTube/Vimeo/direct link)<input name="video_url" type="url" placeholder="https://..." ></label><div class="or">OR</div><label>Upload video file (max 500 MB)<input name="video_file" type="file" accept="video/*"></label><button class="btn">Add movie</button></form><p class="muted small">Only add content you own or have permission to distribute. For production, use durable object storage for uploaded videos.</p></section>
  <section class="panel"><h2>Movie catalogue</h2>${movies.length?`<div class="table-wrap"><table><tr><th>Title</th><th>Category</th><th>Source</th><th>Action</th></tr>${movies.map(m=>`<tr><td>${escapeHtml(m.title)}</td><td>${escapeHtml(m.category)}</td><td>${escapeHtml(m.source_type)}</td><td><a href="/movie/${m.id}">View</a> · <form class="inline" method="post" action="/admin/movies/${m.id}/delete" onsubmit="return confirm('Delete this movie?')"><button class="text-button">Delete</button></form></td></tr>`).join("")}</table></div>`:`<p class="muted">No movies added yet.</p>`}</section>
  <section class="panel"><h2>Recent members</h2><div class="table-wrap"><table><tr><th>Name</th><th>Email</th><th>Subscription expiry</th></tr>${users.map(u=>`<tr><td>${escapeHtml(u.name)}</td><td>${escapeHtml(u.email)}</td><td>${u.expires_at?new Date(u.expires_at).toLocaleString():"No subscription"}</td></tr>`).join("")}</table></div></section>`));
});
app.post("/admin/movies", requireAdmin, upload.single("video_file"), (req,res)=>{
  const title=(req.body.title||"").trim();
  const description=(req.body.description||"").trim();
  const category=(req.body.category||"Other").trim();
  const poster=(req.body.poster_url||"").trim();
  let video=(req.body.video_url||"").trim(), sourceType="embed";
  if (req.file) { video=`/uploads/${req.file.filename}`; sourceType="upload"; }
  if (!title || (!video && !req.file)) {
    req.session.flash="Add a title and either a video link or a video file.";
    return res.redirect("/admin");
  }
  if (!req.file && !isValidHttpUrl(video)) {
    req.session.flash="Enter a valid video URL.";
    return res.redirect("/admin");
  }
  if (poster && !isValidHttpUrl(poster)) { req.session.flash="Poster URL must start with http:// or https://."; return res.redirect("/admin"); }
  db.prepare("INSERT INTO movies(title,description,category,poster_url,video_url,source_type) VALUES(?,?,?,?,?,?)")
    .run(title,description,category,poster,video,sourceType);
  req.session.flash="Movie added successfully.";
  res.redirect("/admin");
});
app.post("/admin/movies/:id/delete", requireAdmin, (req,res)=>{
  const movie=db.prepare("SELECT * FROM movies WHERE id=?").get(Number(req.params.id));
  if (movie && movie.source_type==="upload" && movie.video_url.startsWith("/uploads/")) {
    const file=path.join(UPLOAD_DIR,path.basename(movie.video_url));
    if (fs.existsSync(file)) fs.unlinkSync(file);
  }
  db.prepare("DELETE FROM movies WHERE id=?").run(Number(req.params.id));
  req.session.flash="Movie deleted.";
  res.redirect("/admin");
});

app.get("/health", (_req,res)=>res.json({ok:true,app:"FREDRICK MOVIES"}));
app.use((err,req,res,next)=>{
  console.error(err);
  req.session.flash = err.message && err.message.includes("video") ? err.message : "Something went wrong. Please try again.";
  res.redirect(req.headers.referer || "/");
});

app.listen(PORT, ()=>console.log(`FREDRICK MOVIES running on port ${PORT}`));
