// Protection config
const protectionLevel = 0;

const sameSite = protectionLevel === 0? 'None': 'Lax';
const advancedCsrfProtection = protectionLevel > 1;
const featureRestore = protectionLevel > 2;

// Deps
const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const db = require('./db.js');

const app = express();
app.set('view engine', 'pug');

// Session Handling
let sessions = {};

const cookieOpts = {
  sameSite,
  secure: true,
  httpOnly: true
};

function hasValidSession(req) {
  const userSession = sessions[req.cookies.sessionId];
  return !!userSession && (userSession.expiresAt > Date.now());
}

function authorizer(req, res, next) {
    const validSession = hasValidSession(req);
    const performingLogin = req.path === '/login';
    if(validSession === performingLogin) {
      return res.redirect(303, validSession? '/': '/login?' + new URLSearchParams({ redirect: req.path }));
    }
    next();
}

function buildNewSession(userId) {
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + (5 * 60 * 1000); // 5 mins
  const session = { sessionId, expiresAt, userId };
  sessions[sessionId] = session;
  return session;
}

function resolveUser(req, res, next) {
  const session = sessions[req.cookies.sessionId];
  res.locals.session = session;
  res.locals.user = db.get()[session.userId];
  next();
}

app.use('/static', express.static('static'));
app.use(cookieParser());

if(advancedCsrfProtection) {
  app.post('*', (req, res, next) => {
    if(!req.cookies.csrfProtection) {
      return res.status(403).end();
    }
    next();
  });
  app.all('*', (req, res, next) => {
    res.cookie('csrfProtection', true, { ...cookieOpts, sameSite: 'Strict' });
    next();
  })
}
app.use(authorizer);
app.use(express.urlencoded({ extended: true }));
app.use('/login', (req, res, next) => {
  const { username = '', password = '', redirect = '/' } = (req.method === 'POST' || advancedCsrfProtection)? req.body: req.query;
  if(db.get()[username]?.password === password) {
    const { sessionId, expiresAt } = buildNewSession(username);
    res.cookie('sessionId', sessionId, { ...cookieOpts, expires: new Date(expiresAt) });
    res.redirect(303, redirect);
  } else {
    next()
  }
});
app.get('/login', (req, res) => {
  res.locals.redirect = req.query.redirect;
  if(featureRestore) {
    const { username = '', password = '' } = req.query;
    res.locals.username = username;
    res.locals.password = password;
  }
  res.render('login');
});
app.post('/login', (req, res) => {
  res.status(401).render('unauthorized');
});

// App functionality
app.use(resolveUser);
app.get('/', (req, res) => res.render('index'));
app.get('/information', (req, res) => res.render('information'));
app.get('/note', (req, res) => res.render('note'));
app.post('/note', (req, res) => {
  db.update(accounts => {
    accounts[res.locals.session.userId].note = req.body.note;
    return accounts;
  });
  res.redirect(303, '/note');
});
app.get('/signout', (req, res) => {
  if(advancedCsrfProtection && !req.cookies.csrfProtection) {
    return res.status(403).end()
  }
  delete sessions[req.cookies.sessionId];
  res.clearCookie('sessionId');
  res.redirect(303, '/login');
});

app.listen(3000, () => console.log('Started on port 3000'));
