const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')
const UserService = require('./service/user-service')

module.exports = function (passport) {
  // used to serialize the user for the session
  passport.serializeUser(function (user, done) {
    done(null, user._id)
  })

  // used to deserialize the user
  passport.deserializeUser(async function (id, done) {
    await UserService.getById(id)
      .then((res) => {
        done(null, res)
      })
      .catch((err) => done(err, null))
  })

  passport.use(
    new LocalStrategy(
      {
        // Passport uses "username" and "password", so we override with the names that we want those fields to have
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true, // allows us to pass back the entire request to the callback
      },

      /**
       * This is the Auth handler. We check for a valid user phone and authenticate if found
       */
      async function (req, email, password, done) {
        const user = await UserService.getOneByField('email', email)

        // Check for valid user
        if (!user) {
          return done('Invalid credentials', false)
        }
        // Check for valid auth
        const passwordMatch = await bcrypt.compare(password, user.password)
        if (!passwordMatch) {
          return done('Invalid credentials', false)
        }

        // All is well, return successful user
        return done(null, user)
      }
    )
  )
}
Route file
const express = require('express')
const passport = require('passport')
const AccessMiddleware = require('./access')

const router = express.Router()

const errorResponse = (res, error) => {
  res.status(400).json({ success: false, error })
}

router.get('/test', (req, res) => {
  res.json({ success: true, message: 'Test API route working fine!' })
})

router.get('/authenticated-only', AccessMiddleware.hasAccess, (req, res) => {
  res.json({ success: true, message: 'You have auth access!' })
})

router.get('/admin-only', AccessMiddleware.hasAdminAccess, (req, res) => {
  res.json({ success: true, message: 'You have admin access!' })
})

router.post('/login', (req, res, next) => {
  const { email, password } = req.body
  if (!email || !password) {
    return errorResponse(res, 'Invalid credentials')
  }

  // Authenticate the user using the credentials provided
  passport.authenticate('local', { session: true }, function (err, user) {
    if (err) {
      return errorResponse(res, 'Invalid credentials')
    }

    // When using passport with callback, we have to manually call req.login to set the Cookie
    req.login(user, async () => {
      res.json({ success: true, user })
    })
  })(req, res, next)
})

module.exports = router
exports.errorResponse = errorResponse

// Index.js file

require('dotenv').config()
const express = require('express')
const passport = require('passport')
const path = require('path')
const compression = require('compression')
const cookieParser = require('cookie-parser')
const session = require('cookie-session')
const { COOKIE_NAME } = require('../src/common/config')

// Read env variables
const port = process.env.PORT || 3001
const secret = process.env.APP_SECRET
const env = process.env.NODE_ENV || 'development'
const isLocal = env === 'development'

// Export app in order to be imported in /routes
const app = (module.exports = express())

// Load DB Connection and Register Schema
require('./database')

/* Express setup */
app.use(compression())
app.use(express.static(path.join(__dirname, '../build')))
// Parse JSON bodies (as sent by API clients)
app.use(express.json())
// Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded({ extended: true }))

/* Session Setup */
app.use(cookieParser()) // read cookies (needed for auth)
if (!isLocal) {
  app.set('trust proxy', 1)
}
app.use(
  session({
    httpOnly: false,
    name: COOKIE_NAME,
    keys: [secret],
    secure: !isLocal,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  })
)

/* Session management with Passport */
app.use(passport.initialize())
app.use(passport.session())
require('./passport')(passport)

/* Routes */
// Other routes (e.g. APIs)
require('./routes')

// Default app route
app.get('/*', function (req, res) {
  // Force redirect to HTTPS because cookie is set to secure: true
  if (!isLocal && req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`)
  } else {
    res.sendFile(path.resolve(__dirname, '../build', 'index.html'))
  }
})

app.listen(port, () => console.log('Server started on port', port))

API.js
const express = require('express')
const passport = require('passport')
const AccessMiddleware = require('./access')

const router = express.Router()

const errorResponse = (res, error) => {
  res.status(400).json({ success: false, error })
}

router.get('/test', (req, res) => {
  res.json({ success: true, message: 'Test API route working fine!' })
})

router.get('/authenticated-only', AccessMiddleware.hasAccess, (req, res) => {
  res.json({ success: true, message: 'You have auth access!' })
})

router.get('/admin-only', AccessMiddleware.hasAdminAccess, (req, res) => {
  res.json({ success: true, message: 'You have admin access!' })
})

router.post('/login', (req, res, next) => {
  const { email, password } = req.body
  if (!email || !password) {
    return errorResponse(res, 'Invalid credentials')
  }

  // Authenticate the user using the credentials provided
  passport.authenticate('local', { session: true }, function (err, user) {
    if (err) {
      return errorResponse(res, 'Invalid credentials')
    }

    // When using passport with callback, we have to manually call req.login to set the Cookie
    req.login(user, async () => {
      res.json({ success: true, user })
    })
  })(req, res, next)
})

module.exports = router
exports.errorResponse = errorResponse

// Access.js file

const ROLES = require('../../src/common/roles')

/** Access middleware to ensure user is allowed to access certain routes */
const AccessMiddleware = {
  hasAccess: (req, res, next) => {
    if (!req.isAuthenticated()) {
      req.session.redirectTo = req.originalUrl
      return res.status(401).json({ success: false, error: 'unauthorized' })
    }

    next()
  },

  hasAdminAccess: (req, res, next) => {
    if (!req.isAuthenticated() || req.user.role !== ROLES.ADMIN) {
      req.session.redirectTo = req.originalUrl
      return res.status(401).json({ success: false, error: 'unauthorized' })
    }

    next()
  },
}

module.exports = AccessMiddleware

// Srever-services.js

const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const UserModel = mongoose.model('User')

const HASH_SALT = 15

const UserService = {
  getById: (id) => {
    return UserModel.findById(id)
  },

  getOneByField: (fieldName, fieldValue) => {
    return UserModel.findOne({ [fieldName]: fieldValue })
  },

  add: async ({ name, email, password, role }) => {
    const options = { upsert: true, new: true, setDefaultsOnInsert: true }
    const hashedPassword = await bcrypt.hash(password, HASH_SALT)

    const result = await UserModel.findOneAndUpdate(
      { email },
      { name, email, password: hashedPassword, role },
      options
    )
    return { ...result._doc }
  },
}

module.exports = UserService


// input Default User.js
const ROLES = require('../../src/common/roles')
const UserService = require('../service/user-service')

  /** Insert some default users */
  ; (() => {
    // Regular user
    const regularUser = {
      email: 'user@test.com',
      password: 'password',
      role: ROLES.USER,
      name: 'User',
    }
    UserService.add(regularUser).then((result) => {
      console.log('Regular user:', regularUser.email)
    })

    // Admin
    const admin = {
      email: 'admin@test.com',
      password: 'password',
      role: ROLES.ADMIN,
      name: 'Admin',
    }
    UserService.add(admin).then((result) => {
      console.log('Admin user:', admin.email)
    })
  })()

// Schema index.js file
const mongoose = require('mongoose')
mongoose.set('useCreateIndex', true)
const dbUrl = process.env.DB_URI

// Connect DB
mongoose.connect(dbUrl, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
  retryWrites: false,
})

// Register Schema
require('./schema')

// Insert some default users
require('./_insertDefaultUsers')

// Schema.js file
const mongoose = require('mongoose')

// Define Schemas
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    required: true,
  },
})

// Register Models on Schema
mongoose.model('User', new mongoose.Schema(userSchema, { timestamps: true }))




// ///////////////////////////////////////////////////
const express = require('express');
const router = express.Router();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const User = require('../model/user');
const configAuth = require('../config/auth');

const myModule = 'auth';

passport.use(new GoogleStrategy({
  clientID: configAuth.googleAuth.clientID,
  clientSecret: configAuth.googleAuth.clientSecret,
  callbackURL: configAuth.googleAuth.callbackURL,
},
  function (token, refreshToken, profile, done) {
    process.nextTick(function () {
      User.findOne({ where: { 'google.id': profile.id } }).then((row) => {
        let user = row.get();
        if (user) {
          return done(null, user);
        } else {
          let newUser = {};
          newUser.google.id = profile.id;
          newUser.google.token = token;
          newUser.google.name = profile.displayName;
          newUser.google.email = profile.emails[0].value;
          User.create(newUser).then(() => {
            return done(null, newUser);
          });
        }
      });
    });

  }));

passport.use(new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
  passReqToCallback: true
}, function (req, username, password, done) {
  User.findOne({
    where: {
      username: username
    }
  })
    .then((row) => {
      if (!row) return done(null, false, 'Username Tidak Ditemukan, Silakan Coba Lagi');
      let user = row.get();
      if (!user.status_user) return done(null, false, 'Akun anda belum aktif, Silakan Kontak Administrator Diskominfo Kota Tanjungpinang');
      User.comparePassword(password, user.paswd, function (err, isMatch) {
        if (err) throw err;
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, 'Password Salah, Silakan Coba Lagi');
        }
      });
    });
}));

passport.serializeUser(function (user, done) {
  done(null, user.id_user);
});

passport.deserializeUser(function (id, done) {
  User.findById(id).then((user) => {
    done(null, user.get());
  });
});

router.get('/', isLoggedIn, function (req, res, next) {
  let data = { title: 'Login', menu: 'login' };
  data = Object.assign(data, res.locals);
  data = Object.assign(data, { 'module': myModule, 'adm_url': res.locals.adm_url + myModule + '/' });
  res.render('login/login', data);
});

/*router.post('/', passport.authenticate('local'), function(req, res) {
    console.log( req );
    res.json(true);
    res.end();
});*/

router.post('/', passport.authenticate('local'), function (req, res, next) {
  passport.authenticate('local', function (err, user, info) {
    if (err) { return next(err); }
    if (!user) { return res.status(400).json(info); }
    req.logIn(user, function (err) {
      if (err) { return next(err); }
      return res.json(info);
    });
  })(req, res, next);
});

router.get('/logout', function (req, res) {
  req.logout();
  req.flash('success_msg', 'Anda berhasil keluar');
  res.redirect('/auth');
});

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback',
  passport.authenticate('google', {
    successRedirect: '/profile',
    failureRedirect: '/'
  }));


function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    res.redirect('/adm');
  } else {
    return next();
  }
}

module.exports = router;


// ///////////////////////////////////////////


const server = require('express').Router();
const passport = require('passport');
const crypto = require('crypto');
const { User } = require('../db.js');

//checks if password has > 8 chars
function isValidPassword(password) {
  if (password.length >= 8) {
    return true;
  }
  return false;
}

//uses a regex to check if email is valid
function isValidEmail(email) {
  const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(String(email).toLowerCase());
}

//handles register POST
server.post('/register', async function (req, res, next) {
  const salt = crypto.randomBytes(64).toString('hex');
  const password = crypto.pbkdf2Sync(req.body.password, salt, 10000, 64, 'sha512').toString('base64');

  if (!isValidPassword(req.body.password)) {
    return res.json({ status: 'error', message: 'La contraseña debe tener 8 o más carácteres' });
  }
  if (!isValidEmail(req.body.email)) {
    return res.json({ status: 'error', message: 'Email address not formed correctly.' });
  }

  try {
    const user = await User.create({
      first_name: req.body.first_name,
      last_name: req.body.last_name,
      adress: req.body.adress,
      email: req.body.email,
      active: true,
      password: password,
      salt: salt,
      admin: false
    });
    if (user) {
      passport.authenticate('local', function (err, user, info) {
        if (err) { return next(err); }
        if (!user) {
          return res.json({ status: 'error', message: info.message, err });
        }
        //Una vez registrado el usuario, hacemos login automaticamente
        req.logIn(user, function (err) {
          if (err) { return next(err); }
          return res.json({ status: 'ok' });
        });
      })(req, res, next);
    }
  } catch (err) {
    console.log(err)
    return res.json({ status: 'error', message: 'Esta dirección de email ya está registrada' });
  }
});
//S70Crear-Ruta-para-password-reset
//POST /users/:id/passwordReset
server.put('/:id/passwordReset', (req, res, next) => {
  const { id } = req.params;
  const salt = crypto.randomBytes(64).toString('hex')
  const password = crypto.pbkdf2Sync(req.body.password, salt, 10000, 64, 'sha512').toString('base64')

  User.findByPk(id)
    .then((user) => {
      if (user) {
        user.password = password
        user.salt = salt
        return user.save()
      }
    }).then((user) => {
      res.sendStatus(200);
    }).catch(next)
})

server.put('/promote/:id', (req, res, next) => {
  const userChange = req.params.id;
  User.update({
    admin: true
  }, { where: { id: userChange } })
    .then(change => {
      res.sendStatus(200)
    }).catch(err => {
      next(err);
      res.status(400);
    })
})
// ARTURO
server.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) {
      return res.status(400).json({ status: 'error', message: info.message, err });
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      return res.json({ status: 'ok', user }); //Tambien anda con send(user) o send(req.user)
    });
  })(req, res, next);
  // la funcion authenticate requiere de otra funcion que debe ser invocada, por eso pasamos el (req, res, next). Es "magia" de passport
});

// Luego exportar FUNCION PARA CORROBORAR QUE ESTE AUTENTICADO, SE USARA EN EL FUTURO

function isAutenticated(req, res, next) {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.status(401).send('Para acceder a este recurso debes estar logueado')
  }
}

server.get('/logout', isAutenticated, (req, res) => {
  req.logOut();
  res.redirect('/');
});


server.get('/me', isAutenticated, (req, res) => {
  res.json(req.user);
});


module.exports = server, isAutenticated;