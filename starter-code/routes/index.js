const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const saltRounds = 10;
const User = require("../models/user");

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index", req);
});
router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});
router.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const salt = bcrypt.genSaltSync(saltRounds);
  const hashPass = bcrypt.hashSync(password, salt);

  User.findOne({ username: username }).then(result => {
    if (username !== result) {
      res.render("auth/signup", {
        errorMessage: "Username already exists. Try again."
      });
    } else {
      User.create({
        username,
        password: hashPass
      })
        .then(_ => res.redirect("/"))
        .catch(error => console.log(error));
    }
  });
});

router.get("/login", (req, res, next) => {
  res.render("auth/login");
});

router.post("/login", (req, res, next) => {
  const theUsername = req.body.username;
  const thePassword = req.body.password;

  User.findOne({ username: theUsername })
    .then(user => {
      if (!user) {
        res.render("auth/login", {
          errorMessage: "The username doesn't exist."
        });
        return;
      }
      if (bcrypt.compareSync(thePassword, user.password)) {
        // Save the login in the session!
        req.session.currentUser = user;
        res.redirect("/");
      } else {
        res.render("auth/login", {
          errorMessage: "Incorrect password"
        });
      }
    })
    .catch(error => {
      next(error);
    });
});
router.get("/main", isLoggedIn, (req, res, next) => {
  res.render("main");
});
router.get("/private", isLoggedIn, (req, res, next) => {
  res.render("private");
});

function isLoggedIn(req, res, next) {
  if (req.session.currentUser) {
    next();
  } else {
    res.redirect("/login"); //    |
  }
}

router.get("/logout", (req, res, next) => {
  req.session.destroy(err => {
    // can't access session here
    res.redirect("/login");
  });
});

module.exports = router;
