const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const key = fs.readFileSync('./key.pem');
const cert = fs.readFileSync('./cert.pem');
require('dotenv').config()

Object.prototype.forEach = function (callback){
  Object.keys(this).forEach(key => {
    callback(key, this[key]);
  });
}

const app = express();
const server = require('https').createServer({key: key, cert: cert },app);
const { Server } = require("socket.io");
const io = new Server(server);

// Configure JSON body parsing
app.use(cors());
app.use(express.json());

app.use((req,res,next) => {
  token = req.get('Authorization');

  if(!token) {
    req.authorization = { 
      type: "none", 
      error: "header empty or invalid"
    };
    token = "";
  }

  jwt.verify(token.replace(/^Bearer /, ''), process.env.SECRET,(error, decoded) => {
    if (error) {
      req.authorization = { 
        type: "none",
        error: error.message
      };
    } else {
      req.authorization = { 
        type: "bearer",
        scopes: decoded.scopes,
        token: token 
      };

      if(decoded.hasOwnProperty('userId')) {
        req.authorization.subjectType = "user";
        req.authorization.subjectId = decoded.userId;
      }else if(decoded.hasOwnProperty('deviceId')) {
        req.authorization.subjectType = "device";
        req.authorization.subjectId = decoded.deviceId;
      }else {
        req.authorization.subjectType = "other";
        req.authorization.subjectId = null;
      }
    }
    next();
  });
})

// Connect to MongoDB
mongoose.connect(`mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.kwccfg3.mongodb.net/?retryWrites=true&w=majority`, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB', err));

// Create a user schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const positionReportSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    required: true
  },
  location: {
    type: [Number],
    required: true
  }
});

const deviceSchema = new mongoose.Schema({
  displayName: {
    type: String,
    required: true
  },
  model: {
    type: String,
    required: true
  },
  IMEI: {
    type: String,
    unique: true,
    sparse: true
  },
  EAN: {
    type: String,
    unique: true,
    sparse: true
  },
  originalOwner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  deviceType: {
    type: String,
    enum: ['phone', 'tablet', 'laptop', 'watch', 'tag'],
    required: true
  },
  MACAddress: {
    type: String,
    required: function() {
      return this.deviceType === 'tag';
    }
  },
  positionReports: [positionReportSchema]
});

const Device = mongoose.model('Device', deviceSchema);
const User = mongoose.model('User', userSchema);

// Routes
app.post('/register', async (req, res, next) => {
  try {
    const { username, password, scopes } = req.body;

    // Check if the username is already taken
    const existingUser = await User.findOne({ username }).exec();
    if (existingUser) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    scopes.forEach(scope => {
      if(!scope.id) {
        res.status(400).json({ error: 'Scope formatting error' });
        next();
      }

      if(scope.id.includes("device")){
        scope.params.devices.forEach(device => {
          if(device === "user-owned"){
            //here add code that will translate the user-owned tag into devices owned indefinetely
          } else if(/^from-token:([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)$/.test(device)){ 
            //here add code that will validate the foreign access token 
            //and translate it into devices owned with expiration date
          }
        })
      }
    });

    const token = jwt.sign({ 
      userId: newUser._id,
      scopes: scopes,
    }, process.env.SECRET);

    res.json({ message: 'Registration successful', token });
  } catch (error) {
    console.error('Error during registration', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password, scopes } = req.body;

    // Check if the user exists
    const user = await User.findOne({ username }).exec();
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // Check if the password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    scopeiterator = 0;
    scopes.forEach(scope => {
      if(!scope.id) {
        res.status(400).json({ error: 'Scope formatting error' });
      }
      if(scope.id.includes("device") && scope.id !== "device.add") {
        scope.params.devices.forEach(device => {
          if(device === "user-owned"){
            // scope.params.devices.splice(scope.params.devices.indexOf(device), 1);
            // Device.find({ originalOwner: user._id }).exec().then(devices => {
            //   devices.forEach(device => {
            //     scope.params.devices.append(device._id)
            //   })
            // });
          } else if(/^from-token:([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)$/.test(device)){ 
            //here add code that will validate the foreign access token 
            //and translate it into devices owned with expiration date
          }
        })
        if(scope.params.devices.length === 0) scopes.splice(scopeiterator, 1);
      }
      scopeiterator += 1;
    });

    if(scopes.length === 0) {
      return res.status(400).json({ error: "Scopeless tokens can't be obtained" });
    }

    const token = jwt.sign({ 
        userId: user._id,
        scopes: scopes,
    }, process.env.SECRET);

    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Error during login', error);
    //res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/register-device', async (req, res) => {
  try {
    console.log(req.authorization)
    if(req.authorization.subjectType !== "user" || !req.authorization.scopes.some(scope => scope.id === 'device.add')){
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { displayName, model, IMEI, EAN, deviceType, MACAddress } = req.body;

    // Validate required fields
    if (!displayName || !model || !deviceType) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const originalOwner = req.authorization.subjectId;

    // Create new device object
    const newDevice = new Device({
      displayName,
      model,
      IMEI,
      EAN,
      originalOwner,
      deviceType,
      MACAddress
    });

    // Save the device to the database
    await newDevice.save();

    return res.status(200).json({ message: 'Device registered successfully' , id: newDevice._id });
  } catch (error) {
    console.error('Failed to register device', error);
    return res.status(500).json({ error: 'Failed to register device' });
  }
});

app.post("/email-lookup", async (req, res) => {
  console.log("someone hittin da method",req.body)
  const email = req.body.email;
  try {
    const user = await User.findOne({ username: email }).exec();

    if (user) {
      // Email is already registered
      res.json({ status: "registered" });
    } else {
      // Email is not registered
      res.json({ status: "unregistered" });
    }

  } catch (error) {
    // Handle any errors that occurred during the database query
    console.error(error);
    res.status(500).json({ status: "error" });
  }
});
  
io.on("connection", (socket) => {
  console.log("a user connected");
  token = socket.handshake.headers.authorization;

  if(!token) {
    socket.authorization = { 
      type: "none", 
      error: "header empty or invalid"
    };
    token = "";
  }

  jwt.verify(token.replace(/^Bearer /, ''), process.env.SECRET,(error, decoded) => {
    if (error) {
      socket.authorization = { 
        type: "none",
        error: error.message
      };
    } else {
      socket.authorization = { 
        type: "bearer",
        scopes: decoded.scopes,
        token: token 
      };

      if(decoded.hasOwnProperty('userId')) {
        socket.authorization.subjectType = "user";
        socket.authorization.subjectId = decoded.userId;
      }else if(decoded.hasOwnProperty('deviceId')) {
        socket.authorization.subjectType = "device";
        socket.authorization.subjectId = decoded.deviceId;
      }else {
        socket.authorization.subjectType = "other";
        socket.authorization.subjectId = null;
      }
    }
  });
  console.log(socket.authorization);
  if(socket.authorization.type === "none") socket.disconnect();

  if(socket.authorization.scopes.some(scope => scope.id === 'device.readPosition')){
    const scope = socket.authorization.scopes.find(scope => scope.id === 'device.readPosition')
    if(scope.params.devices.includes("user-owned")){
      socket.join("devices-user-"+socket.authorization.subjectId)
      console.log("User has permission to read position\nAdding user to devices-user-"+socket.authorization.subjectId+" room")
      Device.find({ originalOwner: socket.authorization.subjectId }).exec().then(devices => {
        devices.forEach(device => {
          sanitizeddevice = device
          sanitizeddevice.originalOwner = null;
          sanitizeddevice.positionReports = sanitizeddevice.positionReports.filter(item => new Date() - item.timestamp <= 24 * 60 * 60 * 1000);
          socket.emit("new-device", sanitizeddevice)
          console.log(sanitizeddevice)
        })
      });
    }
  }

  socket.on("location-report", (data) => {
    const { deviceId, location } = data;
    console.log(data);
    if(typeof deviceId!== "string" || !Array.isArray(location)) return;
    console.log("datatypes validated");
    if(!socket.authorization.scopes.some(scope => scope.id === 'device.writePosition')) return;
    console.log("permissions prevalidated")
    const scope = socket.authorization.scopes.find(scope => scope.id === 'device.writePosition')

    Device.findById(deviceId).exec().then(device => {
      console.log(device,socket.authorization.subjectId,scope);
      console.log(device.originalOwner == socket.authorization.subjectId,scope.params.devices.includes("user-owned"))
      if(device.originalOwner == socket.authorization.subjectId && scope.params.devices.includes("user-owned")) {
        device.positionReports.push({
          timestamp: Date.now(),
          location
        });
        device.save();
        io.to("devices-user-"+socket.authorization.subjectId).emit("location-report", data);
      }
    })
  })
});

app.use(express.static('public'));

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('listening on *:3000');
});