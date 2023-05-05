require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3003;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * milliseconds)

const fs = require("fs");
const path = require("path");

let ejs = require("ejs");
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

// add isAdmin boolean to every user
async function addUserType() {
  const result = await userCollection.updateMany(
    {},
    { $set: { isAdmin: false } }
  );
  console.log(`${result.modifiedCount} users updated with isAdmin field`);
}
addUserType();

// function to change isAdmin to true for a specific user
async function promoteUser(username) {
  const result = await userCollection.updateOne(
    username.$set({ isAdmin: true })
  );
  console.log(`${result.modifiedCount} users updated with isAdmin field`);
}

// function to change isAdmin to false for a specific user
async function demoteUser(username) {
  const result = await userCollection.updateOne(
    username.$set({ isAdmin: false })
  );
  console.log(`${result.modifiedCount} users updated with isAdmin field`);
}

// function to delete a user
async function deleteUser(username) {
  const result = await userCollection.deleteOne(username);
  console.log(`${result.deletedCount} users deleted`);
}

// function to delete all users
async function deleteAllUsers() {
  const result = await userCollection.deleteMany({});
  console.log(`${result.deletedCount} users deleted`);
}


//app.use(express.static(path.join(__dirname, "img")));

app.get("/", (req, res) => {
  // links to other pages
  var html = `
  <!DOCTYPE html>
  <html>
  <head>
  <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h1 { color: white; }
            a { color: white; }
            li { color: white; }

  </style>
  </head>
  <body>

    <h1>Members Only</h1>
    <br>
    <a href='/about'>about</a>
    <br>
    <a href='/contact'>contact</a>
    <br>
    <a href='/createUser'>sign up</a>
    <br>
    <a href='/login'>login</a>
    <br>
    <a href='/nosql-injection'>nosql-injection</a>
    <br>
    <a href='/logout'>logout</a>    
    <br>
    <a href='/members'>members</a>
    <br>
  </body>
  </html>

    `;
  res.send(html);
});

app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `
       <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h3 { color: white; }
            a { color: white; }
            li { color: white; }

  </style>
      <h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>
      `
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  //If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  var html = `
  
   <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h1 { color: white; }
            a { color: white; }
            li { color: white; }

  </style>
  <h1>Hello ${username}</h1>
  `;
  res.send(html);
  //res.send(`<h1>Hello ${username}</h1>`);
});

app.get("/about", (req, res) => {
  var color = req.query.color;

  res.send(
    "<h1 style='color:" +
      color +
      ";'>SAM TAM [SET 2E DTC]  COMP2537: ASSIGNMENT 1 </h1>"
  );
});

app.get("/contact", (req, res) => {
  var missingEmail = req.query.missing;
  var html = `
  <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h1 { color: white; }
            a { color: white; }
            li { color: white; }

  </style>
  
        <h1>email address:<h1>
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
  if (missingEmail) {
    html += "<br> email is required";
  }
  res.send(html);
});

app.post("/submitEmail", (req, res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.send("Thanks for subscribing with your email: " + email);
  }
});

app.get("/createUser", (req, res) => {
  var html = `
  <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h1 { color: white; }
            a { color: white; }
            li { color: white; }
   

  </style>
    <h1>sign up<h1>
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <input name= 'email' type='text' placeholder='email'>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.get("/login", (req, res) => {
  var html = `
  <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h1 { color: white; }
            a { color: white; }
            li { color: white; }

  </style>
    <h1>log in<h1>
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;
  // add email
  var email = req.body.email;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
    // add email
    email: Joi.string().email().required(),
  });

  const validationResult = schema.validate({ username, password, email });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/createUser");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    password: hashedPassword,
    // add email
    email: email,
  });
  console.log("Inserted user");

  var html = `
  <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h1 { color: white; }
            a { color: white; }
            li { color: white; }

  </style>
  <h1>successfully created user ${username}</h1>;
  <br>
  <a href='/'>home</a>
  <a href='/login'>login</a>
  `;
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;
  // add email
  var email = req.body.email;

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");

    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    var html = `
    <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h1 { color: white; }
            a { color: white; }
            li { color: white; }

  </style>
    <h1>Invalid username </h1>
    <br>
    <a href='/'>home</a>
    <br>
    <a href='/login'>Try Again  </a>
    `;
    res.send(html);
    //res.redirect("/login");

    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedIn");
    return;
  } else {
    console.log("incorrect password");
    var html = `
    <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h1 { color: white; }
            a { color: white; }
            li { color: white; }

  </style>
    <h1>Invalid password</h1>
    <br>
    <a href='/'>home</a>
    <br>
    <a href='/login'>Try Again  </a>
    `;
    res.send(html);
    //res.redirect("/login");
    return;
  }
});

app.get("/loggedin", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
  }

  res.redirect("/members");
});

// // members page original
// app.use(express.static(path.join(__dirname, "img")));
// app.get("/members", (req, res) => {
//   if (!req.session.username) {
//     res.redirect("/login");
//     return;
//   }

//   const imgDir = path.join(__dirname, "img");
//   fs.readdir(imgDir, (err, files) => {
//     if (err) {
//       console.error(err);
//       res.status(500).send("Server error");
//       return;
//     }

//     const randomIndex = Math.floor(Math.random() * files.length);
//     const randomFile = files[randomIndex];

//     res.send(`
//       <html>
//         <head>
//           <title>Members Page</title>
//           <style>
//             body { background-image: url("/${randomFile}");
//                     background-repeat: no-repeat;
//                     background-size: cover;
//                     background-color: black;
//              }
//             h1 { color: white; }
//             a { color: white; }
//             li { color: white; }

//           </style>
//         </head>
//         <body>
//           <h1>Welcome, ${req.session.username}!</h1>

//           <br />
//           <a href="/logout">Logout</a>
//         </body>
//       </html>
//     `);
//   });
// });

// members page with EJS
// app.use(express.static(path.join(__dirname, "img"))); <--- this uses the 'ABSOLUTE' path; THAT'S WHY IT DOESN'T WORK
app.use(express.static("public")); // <--- this uses the 'RELATIVE' path; THAT'S WHY IT WORKS

app.get("/members", (req, res) => {
  if (!req.session.username) {
    res.redirect("/login");
    return;
  }

  const imgDir = path.join(__dirname, "public/img");
  fs.readdir(imgDir, (err, files) => {
    if (err) {
      console.error(err);
      res.status(500).send("Server error");
      return;
    }

    const randomIndex = Math.floor(Math.random() * files.length);
    const randomFile = files[randomIndex];

    res.render("members", {
      username: req.session.username,
      backgroundImage: `/img/${randomFile}`,
    });
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  var html = `
  <style type="text/css">
  body {
    background-color: black;
    background-repeat: no-repeat;
    background-size: cover;
  }
       h1 { color: white; }
            a { color: white; }
            li { color: white; }

  </style>
    <h1>You are logged out.</h1>

     <br>
    <a href='/login'>login</a> 
    <br>
    <a href='/'>home</a>
    
    `;
  res.send(html);
});

app.get("/cat/:id", (req, res) => {
  var cat = req.params.id;

  if (cat == 1) {
    res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
  } else if (cat == 2) {
    res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
  } else {
    res.send("Invalid cat id: " + cat);
  }
});

// res.render("protectedRoute.ejs", {
//   x: req.session.username,
//   y: imageName,
// });

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send("MY 404 Page not found - 404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
